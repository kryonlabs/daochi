#include "wire.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    char account_id[65];
    char body_hash[65];
    char nonce[65];
    char output[512];
    memset(account_id, 'a', 64);
    memset(body_hash, 'b', 64);
    memset(nonce, 'c', 64);
    account_id[64] = 0;
    body_hash[64] = 0;
    nonce[64] = 0;
    Slice buffer = {.data = output, .length = sizeof output};

    assert(BuildChallengePath(StringView(account_id, 64), buffer));
    assert(strcmp(output,
        "/api/v1/sync/challenge?user_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);

    assert(BuildLoginBody(StringView(account_id, 64),
        StringLiteral("client-1"), StringLiteral("key"), buffer));
    assert(strcmp(output,
        "{\"user_id_hash\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"client_id\":\"client-1\","
        "\"public_key\":\"key\"}") == 0);

    assert(BuildLoginMessageHash(StringView(body_hash, 64),
        StringView(nonce, 64), buffer));
    assert(strcmp(output,
        "daochi-sync-v1\nPOST\n/api/v1/sync/login\n"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n") == 0);

    assert(!BuildChallengePath(StringLiteral("invalid"), buffer));
    assert(output[0] == 0);
    assert(!BuildLoginMessageHash(StringLiteral("invalid"),
        StringView(nonce, 64), buffer));
    assert(output[0] == 0);
    buffer.length = 8;
    assert(!BuildLoginBody(StringView(account_id, 64),
        StringLiteral("client-1"), StringLiteral("key"), buffer));
    assert(output[0] == 0);
    puts("Daochi Ziran wire contract passed");
    return 0;
}
