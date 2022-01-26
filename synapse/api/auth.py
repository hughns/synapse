# Copyright 2014 - 2016 OpenMarket Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging
from typing import TYPE_CHECKING, Optional, Tuple
from urllib.parse import urlencode
from authlib.oauth2.rfc6749.util import scope_to_list

import pymacaroons
from authlib.oauth2.auth import ClientAuth
from authlib.oauth2.rfc7662 import IntrospectionToken
from authlib.oidc.discovery import OpenIDProviderMetadata, get_well_known_url
from netaddr import IPAddress

from twisted.web.client import readBody
from twisted.web.http_headers import Headers
from twisted.web.server import Request

from synapse import event_auth
from synapse.api.auth_blocking import AuthBlocking
from synapse.api.constants import EventTypes, HistoryVisibility, Membership
from synapse.api.errors import (
    AuthError,
    Codes,
    InvalidClientTokenError,
    MissingClientTokenError,
    StoreError,
)
from synapse.appservice import ApplicationService
from synapse.events import EventBase
from synapse.http import get_request_user_agent
from synapse.http.site import SynapseRequest
from synapse.logging.context import make_deferred_yieldable
from synapse.logging.opentracing import active_span, force_tracing, start_active_span
from synapse.storage.databases.main.registration import TokenLookupResult
from synapse.types import Requester, StateMap, UserID, create_requester
from synapse.util import json_decoder
from synapse.util.caches.cached_call import RetryOnExceptionCachedCall
from synapse.util.caches.lrucache import LruCache
from synapse.util.macaroons import get_value_from_macaroon, satisfy_expiry

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


# guests always get this device id.
GUEST_DEVICE_ID = "guest_device"


class _InvalidMacaroonException(Exception):
    pass


class Auth:
    """
    This class contains functions for authenticating users of our client-server API.
    """

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.clock = hs.get_clock()
        self.store = hs.get_datastores().main
        self.state = hs.get_state_handler()
        self._account_validity_handler = hs.get_account_validity_handler()

        self.token_cache: LruCache[str, Tuple[str, bool]] = LruCache(
            10000, "token_cache"
        )

        self._auth_blocking = AuthBlocking(self.hs)

        self._track_appservice_user_ips = hs.config.appservice.track_appservice_user_ips
        self._track_puppeted_user_ips = hs.config.api.track_puppeted_user_ips
        self._macaroon_secret_key = hs.config.key.macaroon_secret_key
        self._force_tracing_for_users = hs.config.tracing.force_tracing_for_users

    async def check_user_in_room(
        self,
        room_id: str,
        user_id: str,
        current_state: Optional[StateMap[EventBase]] = None,
        allow_departed_users: bool = False,
    ) -> EventBase:
        """Check if the user is in the room, or was at some point.
        Args:
            room_id: The room to check.

            user_id: The user to check.

            current_state: Optional map of the current state of the room.
                If provided then that map is used to check whether they are a
                member of the room. Otherwise the current membership is
                loaded from the database.

            allow_departed_users: if True, accept users that were previously
                members but have now departed.

        Raises:
            AuthError if the user is/was not in the room.
        Returns:
            Membership event for the user if the user was in the
            room. This will be the join event if they are currently joined to
            the room. This will be the leave event if they have left the room.
        """
        if current_state:
            member = current_state.get((EventTypes.Member, user_id), None)
        else:
            member = await self.state.get_current_state(
                room_id=room_id, event_type=EventTypes.Member, state_key=user_id
            )

        if member:
            membership = member.membership

            if membership == Membership.JOIN:
                return member

            # XXX this looks totally bogus. Why do we not allow users who have been banned,
            # or those who were members previously and have been re-invited?
            if allow_departed_users and membership == Membership.LEAVE:
                forgot = await self.store.did_forget(user_id, room_id)
                if not forgot:
                    return member

        raise AuthError(403, "User %s not in room %s" % (user_id, room_id))

    async def get_user_by_req(
        self,
        request: SynapseRequest,
        allow_guest: bool = False,
        rights: str = "access",
        allow_expired: bool = False,
    ) -> Requester:
        """Get a registered user's ID.

        Args:
            request: An HTTP request with an access_token query parameter.
            allow_guest: If False, will raise an AuthError if the user making the
                request is a guest.
            rights: The operation being performed; the access token must allow this
            allow_expired: If True, allow the request through even if the account
                is expired, or session token lifetime has ended. Note that
                /login will deliver access tokens regardless of expiration.

        Returns:
            Resolves to the requester
        Raises:
            InvalidClientCredentialsError if no user by that token exists or the token
                is invalid.
            AuthError if access is denied for the user in the access token
        """
        parent_span = active_span()
        with start_active_span("get_user_by_req"):
            requester = await self._wrapped_get_user_by_req(
                request, allow_guest, rights, allow_expired
            )

            if parent_span:
                if requester.authenticated_entity in self._force_tracing_for_users:
                    # request tracing is enabled for this user, so we need to force it
                    # tracing on for the parent span (which will be the servlet span).
                    #
                    # It's too late for the get_user_by_req span to inherit the setting,
                    # so we also force it on for that.
                    force_tracing()
                    force_tracing(parent_span)
                parent_span.set_tag(
                    "authenticated_entity", requester.authenticated_entity
                )
                parent_span.set_tag("user_id", requester.user.to_string())
                if requester.device_id is not None:
                    parent_span.set_tag("device_id", requester.device_id)
                if requester.app_service is not None:
                    parent_span.set_tag("appservice_id", requester.app_service.id)
            return requester

    async def _wrapped_get_user_by_req(
        self,
        request: SynapseRequest,
        allow_guest: bool,
        rights: str,
        allow_expired: bool,
    ) -> Requester:
        """Helper for get_user_by_req

        Once get_user_by_req has set up the opentracing span, this does the actual work.
        """
        try:
            ip_addr = request.getClientIP()
            user_agent = get_request_user_agent(request)

            access_token = self.get_access_token_from_request(request)

            (
                user_id,
                device_id,
                app_service,
            ) = await self._get_appservice_user_id_and_device_id(request)
            if user_id and app_service:
                if ip_addr and self._track_appservice_user_ips:
                    await self.store.insert_client_ip(
                        user_id=user_id,
                        access_token=access_token,
                        ip=ip_addr,
                        user_agent=user_agent,
                        device_id="dummy-device"
                        if device_id is None
                        else device_id,  # stubbed
                    )

                requester = create_requester(
                    user_id, app_service=app_service, device_id=device_id
                )

                request.requester = user_id
                return requester

            user_info = await self.get_user_by_access_token(
                access_token, rights, allow_expired=allow_expired
            )
            token_id = user_info.token_id
            is_guest = user_info.is_guest
            shadow_banned = user_info.shadow_banned

            # Deny the request if the user account has expired.
            if not allow_expired:
                if await self._account_validity_handler.is_user_expired(
                    user_info.user_id
                ):
                    # Raise the error if either an account validity module has determined
                    # the account has expired, or the legacy account validity
                    # implementation is enabled and determined the account has expired
                    raise AuthError(
                        403,
                        "User account has expired",
                        errcode=Codes.EXPIRED_ACCOUNT,
                    )

            device_id = user_info.device_id

            if access_token and ip_addr:
                await self.store.insert_client_ip(
                    user_id=user_info.token_owner,
                    access_token=access_token,
                    ip=ip_addr,
                    user_agent=user_agent,
                    device_id=device_id,
                )
                # Track also the puppeted user client IP if enabled and the user is puppeting
                if (
                    user_info.user_id != user_info.token_owner
                    and self._track_puppeted_user_ips
                ):
                    await self.store.insert_client_ip(
                        user_id=user_info.user_id,
                        access_token=access_token,
                        ip=ip_addr,
                        user_agent=user_agent,
                        device_id=device_id,
                    )

            if is_guest and not allow_guest:
                raise AuthError(
                    403,
                    "Guest access not allowed",
                    errcode=Codes.GUEST_ACCESS_FORBIDDEN,
                )

            # Mark the token as used. This is used to invalidate old refresh
            # tokens after some time.
            if not user_info.token_used and token_id is not None:
                await self.store.mark_access_token_as_used(token_id)

            requester = create_requester(
                user_info.user_id,
                token_id,
                is_guest,
                shadow_banned,
                device_id,
                app_service=app_service,
                authenticated_entity=user_info.token_owner,
            )

            request.requester = requester
            return requester
        except KeyError:
            raise MissingClientTokenError()

    async def validate_appservice_can_control_user_id(
        self, app_service: ApplicationService, user_id: str
    ) -> None:
        """Validates that the app service is allowed to control
        the given user.

        Args:
            app_service: The app service that controls the user
            user_id: The author MXID that the app service is controlling

        Raises:
            AuthError: If the application service is not allowed to control the user
                (user namespace regex does not match, wrong homeserver, etc)
                or if the user has not been registered yet.
        """

        # It's ok if the app service is trying to use the sender from their registration
        if app_service.sender == user_id:
            pass
        # Check to make sure the app service is allowed to control the user
        elif not app_service.is_interested_in_user(user_id):
            raise AuthError(
                403,
                "Application service cannot masquerade as this user (%s)." % user_id,
            )
        # Check to make sure the user is already registered on the homeserver
        elif not (await self.store.get_user_by_id(user_id)):
            raise AuthError(
                403, "Application service has not registered this user (%s)" % user_id
            )

    async def _get_appservice_user_id_and_device_id(
        self, request: Request
    ) -> Tuple[Optional[str], Optional[str], Optional[ApplicationService]]:
        """
        Given a request, reads the request parameters to determine:
        - whether it's an application service that's making this request
        - what user the application service should be treated as controlling
          (the user_id URI parameter allows an application service to masquerade
          any applicable user in its namespace)
        - what device the application service should be treated as controlling
          (the device_id[^1] URI parameter allows an application service to masquerade
          as any device that exists for the relevant user)

        [^1] Unstable and provided by MSC3202.
             Must use `org.matrix.msc3202.device_id` in place of `device_id` for now.

        Returns:
            3-tuple of
            (user ID?, device ID?, application service?)

        Postconditions:
        - If an application service is returned, so is a user ID
        - A user ID is never returned without an application service
        - A device ID is never returned without a user ID or an application service
        - The returned application service, if present, is permitted to control the
          returned user ID.
        - The returned device ID, if present, has been checked to be a valid device ID
          for the returned user ID.
        """
        DEVICE_ID_ARG_NAME = b"org.matrix.msc3202.device_id"

        app_service = self.store.get_app_service_by_token(
            self.get_access_token_from_request(request)
        )
        if app_service is None:
            return None, None, None

        if app_service.ip_range_whitelist:
            ip_address = IPAddress(request.getClientIP())
            if ip_address not in app_service.ip_range_whitelist:
                return None, None, None

        # This will always be set by the time Twisted calls us.
        assert request.args is not None

        if b"user_id" in request.args:
            effective_user_id = request.args[b"user_id"][0].decode("utf8")
            await self.validate_appservice_can_control_user_id(
                app_service, effective_user_id
            )
        else:
            effective_user_id = app_service.sender

        effective_device_id: Optional[str] = None

        if (
            self.hs.config.experimental.msc3202_device_masquerading_enabled
            and DEVICE_ID_ARG_NAME in request.args
        ):
            effective_device_id = request.args[DEVICE_ID_ARG_NAME][0].decode("utf8")
            # We only just set this so it can't be None!
            assert effective_device_id is not None
            device_opt = await self.store.get_device(
                effective_user_id, effective_device_id
            )
            if device_opt is None:
                # For now, use 400 M_EXCLUSIVE if the device doesn't exist.
                # This is an open thread of discussion on MSC3202 as of 2021-12-09.
                raise AuthError(
                    400,
                    f"Application service trying to use a device that doesn't exist ('{effective_device_id}' for {effective_user_id})",
                    Codes.EXCLUSIVE,
                )

        return effective_user_id, effective_device_id, app_service

    async def get_user_by_access_token(
        self,
        token: str,
        rights: str = "access",
        allow_expired: bool = False,
    ) -> TokenLookupResult:
        """Validate access token and get user_id from it

        Args:
            token: The access token to get the user by
            rights: The operation being performed; the access token must
                allow this
            allow_expired: If False, raises an InvalidClientTokenError
                if the token is expired

        Raises:
            InvalidClientTokenError if a user by that token exists, but the token is
                expired
            InvalidClientCredentialsError if no user by that token exists or the token
                is invalid
        """

        if rights == "access":
            # first look in the database
            r = await self.store.get_user_by_access_token(token)
            if r:
                valid_until_ms = r.valid_until_ms
                if (
                    not allow_expired
                    and valid_until_ms is not None
                    and valid_until_ms < self.clock.time_msec()
                ):
                    # there was a valid access token, but it has expired.
                    # soft-logout the user.
                    raise InvalidClientTokenError(
                        msg="Access token has expired", soft_logout=True
                    )

                return r

        # otherwise it needs to be a valid macaroon
        try:
            user_id, guest = self._parse_and_validate_macaroon(token, rights)

            if rights == "access":
                if not guest:
                    # non-guest access tokens must be in the database
                    logger.warning("Unrecognised access token - not in store.")
                    raise InvalidClientTokenError()

                # Guest access tokens are not stored in the database (there can
                # only be one access token per guest, anyway).
                #
                # In order to prevent guest access tokens being used as regular
                # user access tokens (and hence getting around the invalidation
                # process), we look up the user id and check that it is indeed
                # a guest user.
                #
                # It would of course be much easier to store guest access
                # tokens in the database as well, but that would break existing
                # guest tokens.
                stored_user = await self.store.get_user_by_id(user_id)
                if not stored_user:
                    raise InvalidClientTokenError("Unknown user_id %s" % user_id)
                if not stored_user["is_guest"]:
                    raise InvalidClientTokenError(
                        "Guest access token used for regular user"
                    )

                ret = TokenLookupResult(
                    user_id=user_id,
                    is_guest=True,
                    # all guests get the same device id
                    device_id=GUEST_DEVICE_ID,
                )
            elif rights == "delete_pusher":
                # We don't store these tokens in the database

                ret = TokenLookupResult(user_id=user_id, is_guest=False)
            else:
                raise RuntimeError("Unknown rights setting %s", rights)
            return ret
        except (
            _InvalidMacaroonException,
            pymacaroons.exceptions.MacaroonException,
            TypeError,
            ValueError,
        ) as e:
            logger.warning("Invalid macaroon in auth: %s %s", type(e), e)
            raise InvalidClientTokenError("Invalid macaroon passed.")

    def _parse_and_validate_macaroon(
        self, token: str, rights: str = "access"
    ) -> Tuple[str, bool]:
        """Takes a macaroon and tries to parse and validate it. This is cached
        if and only if rights == access and there isn't an expiry.

        On invalid macaroon raises _InvalidMacaroonException

        Returns:
            (user_id, is_guest)
        """
        if rights == "access":
            cached = self.token_cache.get(token, None)
            if cached:
                return cached

        try:
            macaroon = pymacaroons.Macaroon.deserialize(token)
        except Exception:  # deserialize can throw more-or-less anything
            # doesn't look like a macaroon: treat it as an opaque token which
            # must be in the database.
            # TODO: it would be nice to get rid of this, but apparently some
            # people use access tokens which aren't macaroons
            raise _InvalidMacaroonException()

        try:
            user_id = get_value_from_macaroon(macaroon, "user_id")

            guest = False
            for caveat in macaroon.caveats:
                if caveat.caveat_id == "guest = true":
                    guest = True

            self.validate_macaroon(macaroon, rights, user_id=user_id)
        except (
            pymacaroons.exceptions.MacaroonException,
            KeyError,
            TypeError,
            ValueError,
        ):
            raise InvalidClientTokenError("Invalid macaroon passed.")

        if rights == "access":
            self.token_cache[token] = (user_id, guest)

        return user_id, guest

    def validate_macaroon(
        self, macaroon: pymacaroons.Macaroon, type_string: str, user_id: str
    ) -> None:
        """
        validate that a Macaroon is understood by and was signed by this server.

        Args:
            macaroon: The macaroon to validate
            type_string: The kind of token required (e.g. "access", "delete_pusher")
            user_id: The user_id required
        """
        v = pymacaroons.Verifier()

        # the verifier runs a test for every caveat on the macaroon, to check
        # that it is met for the current request. Each caveat must match at
        # least one of the predicates specified by satisfy_exact or
        # specify_general.
        v.satisfy_exact("gen = 1")
        v.satisfy_exact("type = " + type_string)
        v.satisfy_exact("user_id = %s" % user_id)
        v.satisfy_exact("guest = true")
        satisfy_expiry(v, self.clock.time_msec)

        # access_tokens include a nonce for uniqueness: any value is acceptable
        v.satisfy_general(lambda c: c.startswith("nonce = "))

        v.verify(macaroon, self._macaroon_secret_key)

    def get_appservice_by_req(self, request: SynapseRequest) -> ApplicationService:
        token = self.get_access_token_from_request(request)
        service = self.store.get_app_service_by_token(token)
        if not service:
            logger.warning("Unrecognised appservice access token.")
            raise InvalidClientTokenError()
        request.requester = create_requester(service.sender, app_service=service)
        return service

    async def is_server_admin(self, user: UserID) -> bool:
        """Check if the given user is a local server admin.

        Args:
            user: user to check

        Returns:
            True if the user is an admin
        """
        return await self.store.is_server_admin(user)

    async def check_can_change_room_list(self, room_id: str, user: UserID) -> bool:
        """Determine whether the user is allowed to edit the room's entry in the
        published room list.

        Args:
            room_id
            user
        """

        is_admin = await self.is_server_admin(user)
        if is_admin:
            return True

        user_id = user.to_string()
        await self.check_user_in_room(room_id, user_id)

        # We currently require the user is a "moderator" in the room. We do this
        # by checking if they would (theoretically) be able to change the
        # m.room.canonical_alias events
        power_level_event = await self.state.get_current_state(
            room_id, EventTypes.PowerLevels, ""
        )

        auth_events = {}
        if power_level_event:
            auth_events[(EventTypes.PowerLevels, "")] = power_level_event

        send_level = event_auth.get_send_level(
            EventTypes.CanonicalAlias, "", power_level_event
        )
        user_level = event_auth.get_user_power_level(user_id, auth_events)

        return user_level >= send_level

    @staticmethod
    def has_access_token(request: Request) -> bool:
        """Checks if the request has an access_token.

        Returns:
            False if no access_token was given, True otherwise.
        """
        # This will always be set by the time Twisted calls us.
        assert request.args is not None

        query_params = request.args.get(b"access_token")
        auth_headers = request.requestHeaders.getRawHeaders(b"Authorization")
        return bool(query_params) or bool(auth_headers)

    @staticmethod
    def get_access_token_from_request(request: Request) -> str:
        """Extracts the access_token from the request.

        Args:
            request: The http request.
        Returns:
            The access_token
        Raises:
            MissingClientTokenError: If there isn't a single access_token in the
                request
        """
        # This will always be set by the time Twisted calls us.
        assert request.args is not None

        auth_headers = request.requestHeaders.getRawHeaders(b"Authorization")
        query_params = request.args.get(b"access_token")
        if auth_headers:
            # Try the get the access_token from a "Authorization: Bearer"
            # header
            if query_params is not None:
                raise MissingClientTokenError(
                    "Mixing Authorization headers and access_token query parameters."
                )
            if len(auth_headers) > 1:
                raise MissingClientTokenError("Too many Authorization headers.")
            parts = auth_headers[0].split(b" ")
            if parts[0] == b"Bearer" and len(parts) == 2:
                return parts[1].decode("ascii")
            else:
                raise MissingClientTokenError("Invalid Authorization header.")
        else:
            # Try to get the access_token from the query params.
            if not query_params:
                raise MissingClientTokenError()

            return query_params[0].decode("ascii")

    async def check_user_in_room_or_world_readable(
        self, room_id: str, user_id: str, allow_departed_users: bool = False
    ) -> Tuple[str, Optional[str]]:
        """Checks that the user is or was in the room or the room is world
        readable. If it isn't then an exception is raised.

        Args:
            room_id: room to check
            user_id: user to check
            allow_departed_users: if True, accept users that were previously
                members but have now departed

        Returns:
            Resolves to the current membership of the user in the room and the
            membership event ID of the user. If the user is not in the room and
            never has been, then `(Membership.JOIN, None)` is returned.
        """

        try:
            # check_user_in_room will return the most recent membership
            # event for the user if:
            #  * The user is a non-guest user, and was ever in the room
            #  * The user is a guest user, and has joined the room
            # else it will throw.
            member_event = await self.check_user_in_room(
                room_id, user_id, allow_departed_users=allow_departed_users
            )
            return member_event.membership, member_event.event_id
        except AuthError:
            visibility = await self.state.get_current_state(
                room_id, EventTypes.RoomHistoryVisibility, ""
            )
            if (
                visibility
                and visibility.content.get("history_visibility")
                == HistoryVisibility.WORLD_READABLE
            ):
                return Membership.JOIN, None
            raise AuthError(
                403,
                "User %s not in room %s, and room previews are disabled"
                % (user_id, room_id),
            )

    async def check_auth_blocking(
        self,
        user_id: Optional[str] = None,
        threepid: Optional[dict] = None,
        user_type: Optional[str] = None,
        requester: Optional[Requester] = None,
    ) -> None:
        await self._auth_blocking.check_auth_blocking(
            user_id=user_id, threepid=threepid, user_type=user_type, requester=requester
        )


class OAuthBasedAuth(Auth):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self._config = hs.config.auth
        assert self._config.oauth_delegation_enabled, "OAuth delegation is not enabled"
        assert self._config.oauth_delegation_issuer, "No issuer provided"
        assert self._config.oauth_delegation_client_id, "No client_id provided"
        assert self._config.oauth_delegation_client_secret, "No client_secret provided"

        self._http_client = hs.get_proxied_tracing_http_client()
        self._hostname = hs.hostname

        self._issuer_metadata = RetryOnExceptionCachedCall(self._load_metadata)
        self._client_auth = ClientAuth(
            self._config.oauth_delegation_client_id,
            self._config.oauth_delegation_client_secret,
            "client_secret_post",
        )

    async def _load_metadata(self) -> OpenIDProviderMetadata:
        url = get_well_known_url(self._config.oauth_delegation_issuer, external=True)
        response = await self._http_client.get_json(url)
        metadata = OpenIDProviderMetadata(**response)
        # metadata.validate_introspection_endpoint()
        return metadata

    async def _introspect_token(self, token: str) -> IntrospectionToken:
        metadata = await self._issuer_metadata.get()
        introspection_endpoint = metadata.get("introspection_endpoint")
        raw_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": self._http_client.user_agent,
            "Accept": "application/json",
        }

        args = {"token": token, "token_type_hint": "access_token"}
        body = urlencode(args, True)

        # Fill the body/headers with credentials
        uri, raw_headers, body = self._client_auth.prepare(
            method="POST", uri=introspection_endpoint, headers=raw_headers, body=body
        )
        headers = Headers({k: [v] for (k, v) in raw_headers.items()})

        # Do the actual request
        # We're not using the SimpleHttpClient util methods as we don't want to
        # check the HTTP status code and we do the body encoding ourself.
        response = await self._http_client.request(
            method="POST",
            uri=uri,
            data=body.encode("utf-8"),
            headers=headers,
        )

        resp_body = await make_deferred_yieldable(readBody(response))
        # TODO: Let's not worry about 5xx errors & co. for now and just try
        # decoding that as JSON. We should also do some validation of the
        # response
        resp = json_decoder.decode(resp_body.decode("utf-8"))
        return IntrospectionToken(**resp)

    async def get_user_by_req(
        self,
        request: SynapseRequest,
        allow_guest: bool = False,
        rights: str = "access",
        allow_expired: bool = False,
    ) -> Requester:
        access_token = self.get_access_token_from_request(request)
        result = await self.get_user_by_access_token(
            access_token, rights, allow_expired
        )

        return create_requester(
            result.user_id,
            access_token_id=result.token_id,
            is_guest=result.is_guest,
            shadow_banned=result.shadow_banned,
            device_id=result.device_id,
            app_service=None,
            authenticated_entity=result.token_owner,
        )

    async def validate_appservice_can_control_user_id(
        self, app_service: ApplicationService, user_id: str
    ) -> None:
        raise NotImplementedError()

    async def get_user_by_access_token(
        self,
        token: str,
        rights: str = "access",
        allow_expired: bool = False,
    ) -> TokenLookupResult:
        introspection_result = await self._introspect_token(token)

        # TODO: introspection verification should be more extensive, especially:
        #   - verify the scopes
        #   - verify the audience
        if not introspection_result.get("active"):
            raise AuthError(
                403,
                "Invalid access token",
            )

        # TODO: claim mapping should be configurable
        logging.info(f"Introspection result: {introspection_result!r}")
        username: Optional[str] = introspection_result.get("username")
        if username is None or not isinstance(username, str):
            raise AuthError(
                500,
                "Invalid username claim in the introspection result",
            )

        # Let's look at the scope
        scope: Optional[List[str]] = scope_to_list(introspection_result.get("scope"))
        device_id = None
        if scope:
            # Find device_id in scope
            for tok in scope:
                if tok.startswith("urn:matrix:device:"):
                    parts = tok.split(":")
                    if len(parts) == 4:
                        device_id = parts[3]

        user_id = UserID(username, self._hostname)
        user_info = await self.store.get_userinfo_by_id(user_id=user_id.to_string())

        # If the user does not exist, we should create it on the fly
        # TODO: we could use SCIM to provision users ahead of time and listen
        # for SCIM SET events if those ever become standard:
        # https://datatracker.ietf.org/doc/html/draft-hunt-scim-notify-00
        if not user_info:
            await self.store.register_user(user_id=user_id.to_string())
            user_info = await self.store.get_userinfo_by_id(user_id=user_id.to_string())
            if not user_info:
                raise AuthError(
                    500,
                    "Could not create user on the fly",
                )

        if device_id:
            # Create the device on the fly if it does not exist
            try:
                await self.store.get_device(user_id=user_id.to_string(), device_id=device_id)
            except StoreError:
                await self.store.store_device(user_id=user_id.to_string(), device_id=device_id, initial_device_display_name="OIDC-native client")

        return TokenLookupResult(
            user_id=user_id.to_string(),
            is_guest=False,
            shadow_banned=False,
            token_id=None,
            device_id=device_id,
            valid_until_ms=None,
            token_owner=user_id.to_string(),
            token_used=True,
        )

    def validate_macaroon(
        self, macaroon: pymacaroons.Macaroon, type_string: str, user_id: str
    ) -> None:
        raise NotImplementedError()

    def get_appservice_by_req(self, request: SynapseRequest) -> ApplicationService:
        raise NotImplementedError()

    async def is_server_admin(self, user: UserID) -> bool:
        # This should depend on the scope of the token, not just the user
        return False
