"""Writes the authorities the loader's Lucky Stats uploads trust (Nintendont/loader/source/luckystats/ls_roots.inc).

    python tools/make_luckystats_roots.py            # write the file
    python tools/make_luckystats_roots.py --check    # fail if the file is not what this would write

Two lists, from the `certifi` package, each certificate checked against the fingerprint here (as
make_tls_roots.py does for the kernel): luckystats.gg's (Let's Encrypt), which get the player's upload
key, and those of the file store its upload links name (Amazon S3), which never do. If either moves to
another authority, uploads stop ("certificate not trusted") until a SlippWii update adds it.
"""
import argparse
import hashlib
import sys
from pathlib import Path

from make_tls_roots import render

OUT = Path(__file__).resolve().parents[1] / 'Nintendont/loader/source/luckystats/ls_roots.inc'
LISTS = {
    'site': [
        ('ISRG Root X1', '96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6'),
        ('ISRG Root X2', '69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470'),
    ],
    'storage': [
        ('Amazon Root CA 1', '8ecde6884f3d87b1125ba31ac3fcb13d7016de7f57cc904fe1cb97c6ae98196e'),
        ('Amazon Root CA 2', '1ba5b2aa8c65401a82960118f80bec4f62304d83cec4713a19c39c011ea46db4'),
        ('Amazon Root CA 3', '18ce6cfe7bf14e60b2e347b8dfe868cb31d02ebb3ada271569f50343b46db3a4'),
        ('Amazon Root CA 4', 'e35d28419ed02025cfa69038cd623962458da5c695fbdea3c22b0bfb25897092'),
        ('Starfield Services Root Certificate Authority - G2',
         '568d6905a2c88708a4b3025190edcfedb1974a606a13c6e5290fcb2ae63edab5'),
    ],
}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--check', action='store_true', help='compare with the file instead of writing it')
    args = ap.parse_args()
    import certifi
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    by_print = {hashlib.sha256(c.public_bytes(Encoding.DER)).hexdigest(): c
                for c in x509.load_pem_x509_certificates(Path(certifi.where()).read_bytes())}
    text = '/* Written by tools/make_luckystats_roots.py: do not edit. */\n'
    for name, roots in LISTS.items():
        certs = []
        for root in roots:
            cert = by_print.get(root[1])
            if cert is None or f'CN={root[0]}' not in cert.subject.rfc4514_string() or cert.subject != cert.issuer:
                sys.exit(f'{root[0]}: not in {certifi.where()} with that fingerprint')
            certs.append((root, cert))
        part = render(certs)
        part = part.replace('Written by tools/make_tls_roots.py: do not edit. The roots the kernel trusts (so_tls.c):',
                            'ls_http.c: trusted for the ' + ('site:' if name == 'site' else 'file store:'))
        text += part.replace('so_tls_roots', f'ls_{name}_roots').replace('so_root', f'ls_{name}')
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding='utf-8') != text:
            sys.exit(f'{OUT} is not what this tool writes: run it without --check')
        print(f'{OUT.name}: as written by this tool')
        return
    OUT.write_text(text, encoding='utf-8', newline='\n')
    print(f'{OUT}: written')


if __name__ == '__main__':
    main()
