#!/usr/bin/env python3

import requests

from ipaddress import ip_address, IPv4Address, IPv6Address

from cortexutils.analyzer import Analyzer


class HoneypotDBScoreAnalyzer(Analyzer):
    """
    HoneypotDB API docs: https://api.honeypotdb.com/docs
    """

    def __init__(self):
        Analyzer.__init__(self)

    def summary(self, raw):
        taxonomies = []

        if 'api_response' in raw:

            if len(raw['api_response']['data']) > 0:

                level = 'malicious'
                namespace = 'HoneypotDB'
                predicate = 'Score'
                value = raw['api_response']['data'][0]['score']

                taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
            else:
                taxonomies.append(self.build_taxonomy('safe', 'HoneypotDB', 'Score', 0))
        else:
            taxonomies.append(self.build_taxonomy('safe', 'HoneypotDB', 'Score', 0))

        return {"taxonomies": taxonomies}

    def run(self):

        indicator = self.get_data()

        try:
            if self.data_type in ["ip", "hash", "other"]:
                
                api_key = self.get_param('config.API-KEY', None, 'Missing HoneypotDB API key')

                url = 'https://api.honeypotdb.com/score/scores'
                headers = {
                    'Accept': 'application/json',
                    'X-API-KEY': api_key }
                
                params = {'indicator': indicator}

                response = requests.get(url, headers=headers, params=params)

                if not response.ok:
                    self.error('Failed to query HoneypotDB API\n{}'.format(response.text))

                json_response = response.json()

                if not json_response['success']:
                    self.error('HoneypotDB API did not respond with success\n{}'.format(response.text))


                self.report({'api_response': json_response})
            else:
                self.notSupported()
        except Exception as e:
            self.unexpectedError(e)


if __name__ == '__main__':
    HoneypotDBScoreAnalyzer().run()
