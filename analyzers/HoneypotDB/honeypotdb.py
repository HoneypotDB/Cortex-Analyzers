#!/usr/bin/env python3

import requests

from cortexutils.analyzer import Analyzer


class HoneypotDBAnalyzer(Analyzer):
    """
    HoneypotDB API docs: https://api.honeypotdb.com/docs
    """

    def __init__(self):
        Analyzer.__init__(self)

    def run(self):

        try:
            if self.data_type == "ip":
                api_key = self.get_param('config.API_KEY', None, 'Missing HoneypotDB API key')

                indicator = self.get_data()

                url = 'https://api.honeypotdb.com/score/scores'
                headers = {
                    'Accept': 'application/json',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-API-KEY': '%s' % api_key }
                
                params = {'indicator': indicator}

                response = requests.get(url, headers=headers, params=params)

                if response.ok:
                    self.error('Failed to query HoneypotDB API\n{}'.format(response.text))

                json_response = response.json()


                self.report({'values': json_response})
            else:
                self.notSupported()
        except Exception as e:
            self.unexpectedError(e)

    def summary(self, raw):
        taxonomies = []

        if (raw and 'values' in raw) and (len(raw['data'][0]['score']) > 0):

            taxonomies = []
            level = 'malicious'
            namespace = 'HoneypotDB'
            predicate = 'Score'
            value = raw['data'][0]['score']

            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        else:
            taxonomies.append(self.build_taxonomy('safe', 'HoneypotDB', 'Score', 0))

        return {"taxonomies": taxonomies}


if __name__ == '__main__':
    HoneypotDBAnalyzer().run()
