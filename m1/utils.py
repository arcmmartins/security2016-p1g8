import json
"""
not made by me, got from stackoverflow and others
"""


def json_loads_byteified(json_text):
    return _byteify(
        json.loads(json_text, object_hook=_byteify),
        ignore_dicts=True
    )


def _byteify(data, ignore_dicts=False):
    # if this is a unicode string, return its string representation
    if isinstance(data, unicode):
        return data.encode('utf-8')
    # if this is a list of values, return list of byteified values
    if isinstance(data, list):
        return [_byteify(item, ignore_dicts=True) for item in data]
    # if this is a dictionary, return dictionary of byteified keys and values
    # but only if we haven't already byteified it
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
            for key, value in data.iteritems()
            }
    # if it's anything else, return it in its original form
    return data


def primitive_root(prime):
    num_to_check = 0
    primitive_roots = []
    for each in range(1, prime):
        num_to_check += 1
        candidate_prim_roots = []
        for i in range(1, prime):
            modulus = (num_to_check ** i) % prime
            candidate_prim_roots.append(modulus)
            cleanedup_candidate_prim_roots = set(candidate_prim_roots)
            if len(cleanedup_candidate_prim_roots) == len(range(1, prime)):
                primitive_roots.append(num_to_check)
    return primitive_roots

def primes(n):
    """ Returns  a list of primes < n """
    sieve = [True] * n
    for i in xrange(3, int(n ** 0.5) + 1, 2):
        if sieve[i]:
            sieve[i * i::2 * i] = [False] * ((n - i * i - 1) / (2 * i) + 1)
    return [2] + [i for i in xrange(3, n, 2) if sieve[i]]


"""
end of not made by me
"""
