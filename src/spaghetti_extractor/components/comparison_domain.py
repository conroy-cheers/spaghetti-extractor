"""Executable fixture domains over observed input words, not proof summaries."""
from __future__ import annotations

import json

from ..external.argument_domains import checked_argument_domain

DOMAIN_EXIT = 77


def checked_input_domain(value):
    if value is None:
        return None
    if not isinstance(value,dict) or set(value)!={'words','constraints'}:
        raise ValueError('comparison input domain requires words and interval constraints')
    words=value['words']
    if (not isinstance(words,list) or not words or any(not isinstance(w,str) or not w for w in words)
            or len(set(words))!=len(words)):
        raise ValueError('comparison input projections must have distinct nonempty names')
    checked_argument_domain(value['constraints'],argument_words=len(words),context='comparison input domain')
    return value


def admitted_words(domain, words):
    if domain is None or not isinstance(words,list) or len(words)!=len(domain['words']) or any(
            type(w) is not int or not 0<=w<=0xffffffff for w in words):
        raise ValueError('comparison input observation lacks its declared unsigned words')
    return all(row['minimum']<=words[row['argument_index']]<=row['maximum'] for row in domain['constraints'])


def validate_input_observation(plan, observation):
    if plan.get('input_domain') is not None and not admitted_words(plan['input_domain'],observation.get('input_words')):
        raise ValueError('fixture invoked a component outside its declared input domain')


def domain_event(plan, observation):
    if not isinstance(observation,dict) or set(observation)!={'input_domain_exclusion'}:
        raise ValueError('fixture domain exclusion has unexpected observations')
    event=observation['input_domain_exclusion']
    if not isinstance(event,dict) or set(event)!={'component_id','words'}:
        raise ValueError('fixture domain exclusion is malformed')
    identity=event['component_id']
    domains={plan['component_id']:plan.get('input_domain'),**{r['id']:r.get('input_domain') for r in plan.get('dependencies',[])}}
    if not isinstance(identity,str) or identity not in domains or admitted_words(domains[identity],event['words']):
        raise ValueError('fixture exclusion is not justified by the selected input domain')
    return event


def domain_case_status(plan, events):
    if any(e['component_id']!=plan['component_id'] for e in events.values()):
        return 'assumption-violated'
    return 'excluded' if set(events)=={'original','source'} and events['original']==events['source'] else 'domain-mismatch'


def comparison_status(cases):
    statuses={row['status'] for row in cases}
    failures=statuses-{'match','excluded'}
    if failures:
        return 'mismatch' if failures=={'mismatch'} else 'incomplete'
    return 'empty-domain' if statuses=={'excluded'} else 'domain-limited' if 'excluded' in statuses else 'match'


def domain_header(identity, domain):
    """Generate only a test-adapter gate; production component APIs stay intact."""
    checked_input_domain(domain)
    lines=['#ifndef SPX_COMPARISON_INPUT_DOMAIN_H','#define SPX_COMPARISON_INPUT_DOMAIN_H',
        '#include <stdint.h>','#include <stddef.h>','#include <stdio.h>','#include <stdlib.h>',
        'static inline int spx_comparison_word_between(uint32_t v, uint32_t lo, uint32_t hi) { return lo<=v && v<=hi; }',
        'static inline int spx_comparison_admit_input(const uint32_t *words, size_t count) {']
    if domain is None:
        lines+=['  (void)words; (void)count; return 1;']
    else:
        condition=' && '.join(f'spx_comparison_word_between(words[{r["argument_index"]}], UINT32_C({r["minimum"]}), UINT32_C({r["maximum"]}))' for r in domain['constraints']) or '1'
        prefix='{"input_domain_exclusion":{"component_id":'+json.dumps(identity)+',"words":['
        lines += [f'  if (!words || count != {len(domain["words"])}U) exit(78);',
            f'  if ({condition}) return 1;',f'  fputs({json.dumps(prefix)}, stdout);',
            '  for (size_t i=0; i<count; ++i) printf("%s%u", i ? "," : "", (unsigned)words[i]);',
            '  fputs("]}}\\n", stdout);','  return 0;']
    return '\n'.join([*lines,'}','#endif',''])
