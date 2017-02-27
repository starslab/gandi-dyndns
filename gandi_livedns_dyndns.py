#!/usr/bin/env python2

import collections
import json
import os
import random
import re
import subprocess
import time
import urllib2
import requests
import sys

import logging as log
LOG_LEVEL = log.getLevelName(os.getenv('LOG_LEVEL'))
if not isinstance(LOG_LEVEL, int):
  LOG_LEVEL = 20

log.basicConfig(format='%(asctime)-15s [%(levelname)s] %(message)s', level=LOG_LEVEL)

# matches all IPv4 addresses, including invalid ones. we look for
# multiple-provider agreement before returning an IP.
IP_ADDRESS_REGEX = re.compile('\d{1,3}(?:\.\d{1,3}){3}')

def get_external_ip_from_url(url):
  '''Get all the IP addresses found at a given URL.'''

  # open the website, download its data, and return all IP strings found
  # we want to respect some site's filtering on User-Agent.
  data = urllib2.urlopen(url, timeout=10).read()
  addys = IP_ADDRESS_REGEX.findall(data)
  return addys

def get_external_ip(attempts=100, threshold=3):
  '''Return our current external IP address, or None if there was an error.'''

  # load the list of IP address providers
  providers = load_providers()

  # we want several different providers to agree on the address, otherwise we
  # need to keep trying to get agreement. this prevents picking up 'addresses'
  # that are really just strings of four dot-delimited numbers.
  ip_counts = collections.Counter()

  # the providers we're round-robining from
  current_providers = []

  while attempts > 0:
    # reduce our attempt count every time, to ensure we'll exit eventually
    attempts -= 1

    # randomly shuffle the providers list when it's empty so we can round-robin
    # from all the providers. also reset the counts, since double-counting
    # results from the same providers might result in false-positives.
    if not current_providers:
      current_providers = providers[:]
      random.shuffle(current_providers)
      ip_counts = collections.Counter()

    # get the provider we'll try this time
    provider = current_providers.pop()

    try:
      addys = get_external_ip_from_url(provider)

      # add a single address to the counter randomly to help prevent false
      # positives. we don't add all the found addresses to guard against adding
      # multiple false positives for the same site. taking a single random
      # address and then checking it against the other sites is safer. what are
      # the chances that several sites will return the same false-positive
      # number?
      if addys:
        ip = random.choice(addys)
        ip_counts.update({ ip: 1 })
        log.debug('Got IP from provider %s: %s', provider, ip)

      # check for agreeing IP addresses, and return the first address that meets
      # or exceeds the count threshold.
      for ip, count in ip_counts.most_common():
        if count < threshold:
          break
        return ip

    except Exception as e:
      log.warning('Error getting external IP address from %s: %s', provider, e)

      # sleep a bit after errors, in case it's a general network error. if it
      # is, hopefully this will give some time for the network to come back up.
      time.sleep(0.1 + random.random() * 2)

  log.warning('Failed to get an external IP address after %d attempts!', attempts)

  # return None if no agreement could be reached
  return None

def get_local_ip(cmd):
  log.debug('Running shell command: %s', cmd)
  sp = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  out, err = sp.communicate()

  if out:
    log.debug('Command output: %s', out.strip())
  if err:
    log.warning('Command error: %s', err.strip())

  addys = IP_ADDRESS_REGEX.findall(out)

  if addys:
    return addys[0]
  else:
    log.warning('Failed to find a valid IP address in command output!')
    return None

def load_providers():
  '''Load the providers file as a de-duplicated and normalized list of URLs.'''
  with open('providers.json') as f:
    providers = json.load(f)['providers']
  return list(set([p.strip() for p in providers]))

def load_config():
  '''Load the config file from disk.'''
  with open('config.json') as f:
    return json.load(f)

def check_config(conf):
  '''
  Alert the user that they're using invalid config options, such as when
  breaking changes to the config are made.
  '''

  if 'name' in conf:
    log.fatal("Parameter 'name' is now named 'names' and is an array.")
    return False

  # convert old-style configuration, e.g.
  #   "domain": "example.com", "names": [ "foo", "bar", "@" ]
  # to new style:
  #   "domains": { "example.com": [ "foo", "bar", "@" ] }
  if 'domain' in conf and 'names' in conf:
    conf['domains'] = { conf.pop('domain'): conf.pop('names') }

  return True

def test_providers():
  '''Test all IP providers and log the IPs they return.'''

  for provider in load_providers():
    log.debug('IPs found at %s:', provider)

    try:
      for ip in get_external_ip_from_url(provider):
        log.debug('  %s', ip)
    except Exception as e:
      log.warning('Error getting external IP address from %s: %s', provider, e)

def update_ip():
  '''
  Check our external IP address and update Gandi's A-record to point to it if
  it has changed.
  '''

  # load the config file so we can get our variables
  log.debug('Loading config file...')
  config = load_config()
  if not check_config(config):
    sys.exit(2)
  log.debug('Config file loaded.')

  # create a connection to the Gandi production API
  # gandi = GandiServerProxy(config['api_key'])
  ApiKeyHeader = {'X-Api-Key': config['api_key']}

  # see if the record's IP differs from ours
  if 'command' in config:
    log.debug('Getting external IP using local command...')
    external_ip = get_local_ip(config['command'])
  else:
    log.debug('Getting external IP...')
    external_ip = get_external_ip()

  log.debug('External IP is: %s', external_ip)

  # make sure we actually got the external IP
  if external_ip is None:
    log.fatal('Could not get external IP.')
    sys.exit(2)

  for domain in config['domains']:
    # get the current UUID for the configured domain
    log.debug("Getting domain UUID for domain '%s'...", domain)
    r = requests.get('https://dns.beta.gandi.net/api/v5/zones', headers=ApiKeyHeader, timeout=10.0)
    r.raise_for_status() ## Crash the script if we got an error code back from the API
    if r.headers['x-total-count'] < 1:
      log.error('No domains returned by get UUID command with this API key!')
      sys.exit("Bailing out!")
    else:
      found_uuid = False
      for x in r.json():
        if x['name'] == domain:
          zone_uuid = x['uuid']
          found_uuid = True
          break
      if found_uuid == False:
        log.error("Did not find domain {} in UUIDs for this API-Key!".format(domain))
        sys.exit("Bailing out!")
    log.debug("Got domain UUID {} for {}".format(zone_uuid, domain))
    for rec in config['domains'][domain]:
      rec = rec.strip()
      log.debug("Working on entry {} for {}".format(rec, domain))
      url = "https://dns.beta.gandi.net/api/v5/zones/{}/records/{}/A".format(zone_uuid, rec)
      r = requests.get(url, headers=ApiKeyHeader, timeout=10.0)
      if r.status_code != 200:
        log.error("No A record found for {} in {}!".format(rec, domain))
        continue # with next record
      record_ip = r.json()['rrset_values'][0]
      if record_ip == external_ip:
        log.debug("DNS record for {} matches current IP, no update needed".format(rec))
        continue # with next record
      update = {}
      update['rrset_values'] = [external_ip]
      url = "https://dns.beta.gandi.net/api/v5/domains/{}/records/{}/A".format(domain, rec)
      r = requests.put(url, headers=ApiKeyHeader, json=update, timeout=10.0)
      if r.status_code == 201:
        log.debug("API call to update {} succeeded".format(rec))
        continue # with next record
      else:
        log.debug("API call to update {} failed!".format(rec))
        continue # with next record

def main(args):
  # test all providers if specified, otherwise update the IP
  if args[-1] == 'test':
    test_providers()
  else:
    update_ip()

if __name__ == '__main__':
  import sys
  main(sys.argv)
