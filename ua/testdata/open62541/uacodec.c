/* SPDX-License-Identifier: MIT
 *
 * uacodec - throwaway helper that exposes open62541's JSON and XML
 * DataEncodings on stdin/stdout so the go-opcua codecs can be checked against
 * an independent implementation. See README.md in this directory.
 *
 * Protocol: one request per input line, one response per output line.
 *
 *   enc <json|xml> <TypeName> <hex(binary)>   ->  OK <hex(document)>
 *   dec <json|xml> <TypeName> <hex(document)> ->  OK <hex(binary)>
 *
 * A failing request answers "ERR <StatusCodeName>". The binary DataEncoding
 * is the neutral exchange format: both stacks already interoperate on it. */
#include <open62541/types.h>
#include <open62541/types_generated.h>
#include <open62541/util.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const UA_DataType *findType(const char *name) {
    for(size_t i = 0; i < UA_TYPES_COUNT; i++)
        if(strcmp(UA_TYPES[i].typeName, name) == 0)
            return &UA_TYPES[i];
    return NULL;
}

static int unhex(const char *s, UA_ByteString *out) {
    size_t n = strlen(s);
    while(n > 0 && (s[n-1] == '\n' || s[n-1] == '\r')) n--;
    if(n % 2 || UA_ByteString_allocBuffer(out, n / 2 + 1) != UA_STATUSCODE_GOOD)
        return -1;
    out->length = n / 2;
    for(size_t i = 0; i < n / 2; i++) {
        unsigned v;
        if(sscanf(s + 2 * i, "%2x", &v) != 1) return -1;
        out->data[i] = (UA_Byte)v;
    }
    return 0;
}

static void reply(UA_StatusCode rc, const UA_ByteString *out) {
    if(rc != UA_STATUSCODE_GOOD) {
        printf("ERR %s\n", UA_StatusCode_name(rc));
    } else {
        printf("OK ");
        for(size_t i = 0; i < out->length; i++) printf("%02x", out->data[i]);
        printf("\n");
    }
    fflush(stdout);
}

int main(void) {
    char *line = NULL;
    size_t cap = 0;
    while(getline(&line, &cap, stdin) > 0) {
        char op[8], fmt[8], tname[128];
        int off = 0;
        if(sscanf(line, "%7s %7s %127s %n", op, fmt, tname, &off) < 3) {
            printf("ERR BadRequest\n"); fflush(stdout); continue;
        }
        const UA_DataType *type = findType(tname);
        UA_ByteString in = UA_BYTESTRING_NULL, out = UA_BYTESTRING_NULL;
        if(!type || unhex(line + off, &in) != 0) {
            printf("ERR BadRequest\n"); fflush(stdout); continue;
        }
        int json = strcmp(fmt, "json") == 0;
        void *val = UA_new(type);
        UA_StatusCode rc;
        if(strcmp(op, "enc") == 0) {
            rc = UA_decodeBinary(&in, val, type, NULL);
            if(rc == UA_STATUSCODE_GOOD)
                rc = json ? UA_encodeJson(val, type, &out, NULL)
                          : UA_encodeXml(val, type, &out, NULL);
        } else {
            rc = json ? UA_decodeJson(&in, val, type, NULL)
                      : UA_decodeXml(&in, val, type, NULL);
            if(rc == UA_STATUSCODE_GOOD)
                rc = UA_encodeBinary(val, type, &out, NULL);
        }
        reply(rc, &out);
        UA_delete(val, type);
        UA_ByteString_clear(&in);
        UA_ByteString_clear(&out);
    }
    free(line);
    return 0;
}
