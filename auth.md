#

## Credential Scope

* Contains several '/'-separated components:
  - Access Key
  - Timestamp
    - Is of the format YYYYMMDDTHHMMSSZ
  - Nonce
  - Application Id


## Signing Key

Replace the "access key" scope field with the `"NIM1" + secret_key` and
HMAC cascade each component:

```
HMAC(HMAC(HMAC("NIM1" + secret, timestamp), nonce), app_id)
```
 

## Timestamps

| Type             | Variable      | Accuracy   | Description |
| ---------------- | ------------- | ---------- | ----------- |
| Received         | t<sub>r</sub> | Sub-second | Time the message was delivered. |
| Message          | t<sub>m</sub> | Sub-second | Timestamp in the message body. |
| X-NimrodG-SentAt | t<sub>x</sub> | Sub-second | The `X-NimrodG-SentAt` header. Time the message was sent. |
| basic.properties | t<sub>b</sub> | Second     | The timestamp field of `basic.properties` |
| Authorization    | t<sub>a</sub> | Second     | The timestamp in the `Authorization` header. |

* Require t<sub>b</sub> = t<sub>b</sub> = t<sub>m</sub>
  * The sub-second parts of t<sub>m</sub> should be removed before comparison.
  * Do __NOT__ round to the nearest second.
* t<sub>x</sub> is ignored because it has no bearing on validity.
  It only shows the time delta between the message generation and sending.
  This should be negligible. If it needs to be validated, put it in the signed headers list.

## Validation

`timestamp`, `nonce`, and `appid` come from the `Authorization` header.

There's two stages of verification: signature, and semantic.

The first stage of verification is signature verification. Signature verification
is used to verify the authenticity and origin of the message. This consists of the above
signing process.

Semantic verification is applied after signature verification is complete.
It is known that the message came from a trusted source and hasn't been tampered with,
however this doesn't necessarily mean the message is valid.

Requirements of semantic verification:

* The value in the `X-NimrodG-SentAt` header, if provided, __MUST__ be ignored
  for the purposes of verification.
* The `basic.properties` timestamp __MUST__ be provided.
* The `basic.properties` timestamp __MUST__ match that of the __Authorization__ header.
  - The header timestamp should be converted to a `time_t` before comparison.
  - See the `time_t nim1::auth_header_t::_time` field.
* The timestamp in the message payload must be in the same second as all other timestamps.
* The `basic.properties` application id __MUST__ be provided.
* The `basic.properties` application id __MUST__ match that of the __Authorization__ header.
* The `basic.properties` application id __MUST__ equal `"nimrod"`
