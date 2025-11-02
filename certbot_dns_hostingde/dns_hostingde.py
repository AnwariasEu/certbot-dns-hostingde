"""DNS Authenticator for Hosting.de DNS."""
import logging

from requests.exceptions import HTTPError
from lexicon.providers import hostingde

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

DASHBOARD_URL = "https://www.hosting.de/"


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Hosting.de Infrastructure Service DNS

    This Authenticator uses the Hosting.de Infrastructure Service API to fulfill
    a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using Hosting.de for DNS).'
    ttl = 600

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.credentials = None
        self.client = None
        self._setup_credentials()
        self._setup_client()


    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super().add_parser_arguments(add, default_propagation_seconds=30)
        add('credentials', help='HostingDE credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Hosting.de API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Hosting.de credentials INI file',
            {
                'api-token': f'API Token for Hosting.de account, obtained from {DASHBOARD_URL}'
            }
        )

    def _setup_client(self):
        self.client = _HostingDELexiconClient(self.credentials.conf('api-token'), self.ttl)

    def _perform(self, domain, validation_name, validation):
        self.client.add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self.client.del_txt_record(domain, validation_name, validation)



class _HostingDELexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the Hosting.de API via Lexicon.
    """

    def __init__(self, api_token: str, ttl: int):
        super().__init__()

        self.provider = hostingde.Provider({
            'auth_token': api_token,
            'ttl': ttl,
        })

    def _find_domain_id(self, domain):
        """
        Find the domain_id for a given domain.
        Rewrite certbot/plugins/dns_common_lexicon.py to ensure compatibility
        for Lexicon 2.x and 3.x

        :param str domain: The domain for which to find the domain_id.
        :raises errors.PluginError: if the domain_id cannot be found.
        """

        domain_name_guesses = dns_common.base_domain_name_guesses(domain)

        for domain_name in domain_name_guesses:
            try:
                if hasattr(self.provider, 'options'):
                    # For Lexicon 2.x
                    self.provider.options['domain'] = domain_name
                else:
                    # For Lexicon 3.x
                    self.provider.domain = domain_name

                self.provider.authenticate()

                return  # If `authenticate` doesn't throw an exception, we've found the right name
            except HTTPError as e:
                result = self._handle_http_error(e, domain_name)

                if result:
                    raise result from e
            except Exception as e:  # pylint: disable=broad-except
                result = self._handle_general_error(e, domain_name)

                if result:
                    raise result from e

        raise errors.PluginError(f'Unable to determine zone identifier for {domain}'
                                  ' using zone names: {domain_name_guesses}')

    def _handle_http_error(self, e, domain_name):
        hint = None
        if str(e).startswith('400 Client Error:'):
            hint = 'Are your API ID and API Token values correct?'
            return errors.PluginError('Error determining zone identifier for {0}: {1}.{2}'
                                  .format(domain_name, e, ' ({0})'.format(hint) if hint else ''))

    def _handle_general_error(self, e, domain_name):
        if not str(e).startswith('Domain name invalid'):
            return errors.PluginError('Unexpected error determining zone identifier for {domain_name}: {e}')
