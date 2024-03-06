# https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-12---key-capabilities
def capabilities:
  {
    e : "Encrypt",
    E : "Encrypt (entire key)",
    s : "Sign",
    S : "Sign (entire key)",
    c : "Certify",
    C : "Certify (entire key)",
    a : "Authentication",
    A : "Authentication (entire key)",
    r : "Restricted encryption (subkey only use)",
    t : "Timestamping",
    g : "Group key",
    D : "Deprecated",
    "?" : "Unknown capability",
  }
  ;

# https://www.rfc-editor.org/rfc/rfc4880 9.1
def key_algorithms:
  {
    "1" : "RSA (Encrypt or Sign) [HAC]",
    "2" : "RSA Encrypt-Only [HAC]",
    "3" : "RSA Sign-Only [HAC]",
    "16" : "Elgamal (Encrypt-Only) [ELGAMAL] [HAC]",
    "17" : "DSA (Digital Signature Algorithm) [FIPS186] [HAC]",
    "18" : "Reserved for Elliptic Curve",
    "19" : "Reserved for ECDSA",
    "20" : "Reserved (formerly Elgamal Encrypt or Sign)",
    "21" : "Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)"
  }
  ;

def regex_record:
  [
    "^(?<record_type>[^:]+):",
    "(?<validity>[^:]*):",
    "(?<key_length>[^:]*):",
    "(?<key_algorithm>[^:]*):",
    "(?<key_id>[^:]*):",
    "(?<creation_date>[^:]*):",
    "(?<expiration_date>[^:]*):",
    "(?<user_hash>[^:]*):",
    "(?<ownership>[^:]*):",
    "(?<user_id>[^:]*):",
    "((?<signature_class>[^:]*):)?",
    "((?<capabilities>[^:]*):)?",
    "((?<issuer_certificate_fingerprint>[^:]*):)?",
    "((?<flag_field>[^:]*):)?",
    "((?<token_sn>[^:]*):)?",
    "((?<hash_algorithm>[^:]*):)?",
    "((?<curve_name>[^:]*):)?",
    "((?<compliance_flags>[^:]*):)?",
    "((?<last_update>[^:]*):)?",
    "((?<origin>[^:]*):)?",
    "((?<comment>[^:]*))?$"
  ] | join("")
  ;

def valid_validities:
  [
    "-",
    "f",
    "q",
    "s",
    "u",
    "w"
  ]
  ;

# https://github.com/gpg/gnupg/blob/master/doc/DETAILS#field-2---validity
def validity:
  {
    "o" : "Unknown (this key is new to the system)",
    "i" : "The key is invalid (e.g. due to a missing self-signature)",
    "d" : "The key has been disabled",
    "r" : "The key has been revoked",
    "e" : "The key has expired",
    "-" : "Unknown validity (i.e. no value assigned)",
    "q" : "Undefined validity. ‘-’ and ‘q’ may safely be treated as the same value for most purposes",
    "n" : "The key is not valid",
    "m" : "The key is marginal valid.",
    "f" : "The key is fully valid",
    "u" : "The key is ultimately valid. This often means that the secret key is available, but any key may be marked as ultimately valid.",
    "w" : "The key has a well known private part.",
    "s" : "The key has special validity. This means that it might be self-signed and expected to be used in the STEED system.",
  }
  ;

def map_key_record:
  {
    capabilities : .capabilities,
    capabilities_long : (
      .capabilities |
      split("") |
      map(capabilities[.])
    ),
    compliance_flags : .compliance_flags,
    creation_date : .creation_date,
    expiration_date : .expiration_date,
    key_algorithm : key_algorithms[.key_algorithm],
    key_id : .key_id,
    key_length : .key_length,
    origin : .origin, # ??
    ownership : .ownership, # ??
    validity : .validity,
    validity_long : validity[.validity],
  }
  ;

def map_uid_record:
  {
    creation_date : .creation_date,
    user_hash : .user_hash,
    user_id : .user_id,
    validity : .validity,
    validity_long : validity[.validity],
  }
  ;

  [., inputs] |
  map(capture(regex_record)) |
  reduce .[] as $record ([]; (
    . as $a |
    $record |
    if .record_type == "pub" then
      $a + [map_key_record]
    elif .record_type == "fpr" then
      if $a[-1].sub_keys then
        $a[0:-1] + [
          $a[-1] + {
            sub_keys : (
              $a[-1].sub_keys[0:-1] + [
                $a[-1].sub_keys[-1] + {
                  fingerprint : .user_id
                }
              ]
            )
          }
        ]
      else
        $a[0:-1] + [
          $a[-1] + {
            fingerprint : .user_id
          }
        ]
      end
    elif .record_type == "uid" then
      $a[0:-1] + [
        $a[-1] + {
          identities : (
            ($a[-1].identities // []) +
            [map_uid_record]
          )
        }
      ]
    elif .record_type == "sub" then
      $a[0:-1] + [
        $a[-1] + {
          sub_keys : (
            ($a[-1].sub_keys // []) +
            [map_key_record]
          )
        }
      ]
    else
      $a
    end
  ) 
) |
if $valid_only == "true" then
  map(
    if .sub_keys then
      . + {
        sub_keys : [
          .sub_keys[] |
          select(
            .validity as $validity |
            valid_validities |
            index($validity)
          )
        ]
      }
    else
      .
    end
  ) |
  [
    .[] |
    select(
      (
        .validity as $validity |
        valid_validities |
        index($validity)
      ) and
      (.sub_keys | length) > 0
    )
  ]
else
  .
end
