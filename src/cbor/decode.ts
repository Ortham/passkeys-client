// CBOR as used by WebAuthn is fairly limited, see
// https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-conforming-all-classes
// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ctap2-canonical-cbor-encoding-form
// this makes it feasible to implement parsing from scratch.
import { assert, strictEqual } from "../assert";
import { CBOR_TYPE_ARRAY, CBOR_TYPE_BYTE_STRING, CBOR_TYPE_FLOAT, CBOR_TYPE_MAP, CBOR_TYPE_NEGATIVE_INT, CBOR_TYPE_TAG, CBOR_TYPE_TEXT_STRING, CBOR_TYPE_UNSIGNED_INT } from "./common";

export type DecodedValue = bigint | Uint8Array | string | DecodedValue[] | Map<DecodedValue, DecodedValue> | boolean | null | undefined | number;

function getType(byte: number) {
    return byte >> 5;
}

function getTypeInfo(byte: number) {
    return byte & 0b1_1111;
}

function getDataLength(buffer: Uint8Array) {
    // The first byte is the type and arg.
    assert(buffer.byteLength > 0, "Can't get data length with no data");
    const info = getTypeInfo(buffer[0]!);

    let start;
    let end;
    if (info < 24) {
        // Info is the data length.
        start = 1n;
        end = start + BigInt(info);
    } else if (info === 24) {
        assert(buffer.byteLength > 1, 'Expected extra byte for data length');
        // The length is held in the following byte
        const length = buffer[1]!;

        start = 2n;
        end = start + BigInt(length);
    } else if (info === 25) {
        assert(buffer.byteLength > 2, 'Expected 2 extra bytes for data length');
        // Length in 2 bytes this time, in big-endian order.
        const length = (buffer[1]! << 8) | buffer[2]!;

        start = 3n;
        end = start + BigInt(length);
    } else if (info === 26) {
        assert(buffer.byteLength > 4, 'Expected 4 extra bytes for data length');
        // Length in 4 bytes this time.
        const length = (buffer[1]! << 24) | (buffer[2]! << 16) | (buffer[3]! << 8) | buffer[4]!;

        start = 5n;
        end = start + BigInt(length);
    } else if (info === 27) {
        assert(buffer.byteLength > 8, 'Expected 8 extra bytes for data length');
        // Length in 8 bytes this time.
        // JS stores integers as 32-bit numbers, so this can't be read in one go.
        // Unfortunately this means storing the value as a bigint, which means the other branches also need to return bigints.
        const high = (buffer[1]! << 24) | (buffer[2]! << 16) | (buffer[3]! << 8) | buffer[4]!;
        const low = (buffer[5]! << 24) | (buffer[6]! << 16) | (buffer[7]! << 8) | buffer[8]!;

        const length = BigInt(high) << BigInt(32) | BigInt(low);

        start = 9n;
        end = BigInt(start) + length;
    } else {
        throw new Error('Not well-formed CBOR');
    }

    return {
        start,
        end
    };
}

function isSafeAsNumber(bigint: bigint): boolean {
    return BigInt(Number(bigint)) === bigint;
}

function decodeUnsignedInt(buffer: Uint8Array): { value: bigint | number; end: bigint; } {
    assert(buffer.byteLength > 0, "Can't decode unsigned int from no data");
    assert(getType(buffer[0]!) === CBOR_TYPE_UNSIGNED_INT);

    const { start, end } = getDataLength(buffer);

    // For an unsigned int the data length is the value.
    const value = end - start;

    return {
        value: isSafeAsNumber(value) ? Number(value) : value,
        end: start
    };
}

function decodeNegativeInt(buffer: Uint8Array): { value: bigint | number; end: bigint; } {
    assert(buffer.byteLength > 0, "Can't decode negative int from no data");
    assert(getType(buffer[0]!) === CBOR_TYPE_NEGATIVE_INT);

    const { start, end } = getDataLength(buffer);

    // For a negative int the -1 - data length is the value.
    const value = -1n - (end - start);

    return {
        value: isSafeAsNumber(value) ? Number(value) : value,
        end: start
    };
}

function decodeByteString(buffer: Uint8Array): { value: Uint8Array; end: bigint; } {
    assert(buffer.byteLength > 0, "Can't decode byte string from no data");
    assert(getType(buffer[0]!) === CBOR_TYPE_BYTE_STRING);

    const { start, end } = getDataLength(buffer);

    return {
        value: buffer.subarray(Number(start), Number(end)),
        end
    };
}

function decodeTextString(buffer: Uint8Array): { value: string; end: bigint; } {
    // First byte is the type and arg
    assert(buffer.byteLength > 0, "Can't decode text string from no data");
    assert(getType(buffer[0]!) === CBOR_TYPE_TEXT_STRING);

    const { start, end } = getDataLength(buffer);

    buffer = buffer.subarray(Number(start), Number(end))

    return {
        value: new TextDecoder().decode(buffer),
        end
    };
}

function decodeArray(buffer: Uint8Array): { value: DecodedValue[]; end: bigint; } {
    assert(buffer.byteLength > 0, "Can't decode array from no data");
    assert(getType(buffer[0]!) === CBOR_TYPE_ARRAY);

    let { start, end } = getDataLength(buffer);
    let itemCount = end - start;

    let items = [];
    let offset = start;
    while (itemCount > 0) {
        const { value: item, end: itemEnd } = decodeDataItem(buffer.subarray(Number(offset)));
        offset += itemEnd;

        items.push(item);
        itemCount -= 1n;
    }

    return {
        value: items,
        end: offset
    }
}

function decodeMap(buffer: Uint8Array): { value: Map<DecodedValue, DecodedValue>; end: bigint; } {
    assert(buffer.byteLength > 0, "Can't decode map from no data");
    strictEqual(getType(buffer[0]!), CBOR_TYPE_MAP);

    let { start, end } = getDataLength(buffer);
    let itemCount = end - start;

    let entries: [DecodedValue, DecodedValue][] = [];
    let offset = start;
    while (itemCount > 0) {
        const { value: key, end: keyEnd } = decodeDataItem(buffer.subarray(Number(offset)));
        offset += keyEnd;

        const { value, end: valueEnd } = decodeDataItem(buffer.subarray(Number(offset)));
        offset += valueEnd;

        entries.push([key, value]);
        itemCount -= 1n;
    }

    return {
        value: new Map(entries),
        end: offset
    };
}

function decodeTag(_buffer: Uint8Array): never {
    throw new Error('Tags are not supported in WebAuthn CBOR data');
}

function ldexp(float: number, exp: number) {
    return float * Math.pow(2, exp);
}

function decodeFloat(buffer: Uint8Array): { value: boolean | null | undefined | number; end: bigint; } {
    assert(buffer.byteLength > 0, "Can't decode float or simple type from no data");
    assert(getType(buffer[0]!) === CBOR_TYPE_FLOAT);

    const info = getTypeInfo(buffer[0]!);

    if (info < 20) {
        throw new Error('Simple value is unassigned');
    }

    if (info === 20) {
        return {
            value: false,
            end: 1n
        };
    }

    if (info === 21) {
        return {
            value: true,
            end: 1n
        };
    }

    if (info === 22) {
        return {
            value: null,
            end: 1n
        };
    }

    if (info === 23) {
        return {
            value: undefined,
            end: 1n
        };
    }

    if (info === 24) {
        throw new Error('Simple value is unassigned');
    }

    if (info === 25) {
        // big-endian 16-bit float in the following 2 bytes
        // Decode logic adapted from https://www.rfc-editor.org/rfc/rfc8949.html#half-precision

        assert(buffer.byteLength > 2, "Can't decode float16 from no data");
        const half = (buffer[1]! << 8) | buffer[2]!;

        const exp = (half >> 10) & 0x1f;
        const mant = half & 0x3ff;

        let val;
        if (exp === 0) {
            val = ldexp(mant, -24);
        } else if (exp !== 31) {
            val = ldexp(mant + 1024, exp - 25);
        } else {
            val = mant === 0 ? Number.POSITIVE_INFINITY : Number.NaN;
        }

        return {
            value: half & 0x8000 ? -val : val,
            end: 3n
        };
    }

    if (info === 26) {
        // big-endian 32-bit float in the following 4 bytes
        return {
            value: new DataView(buffer.buffer).getFloat32(1, false),
            end: 5n
        };
    }

    if (info === 27) {
        // big-endian 64-bit float in the following 8 bytes
        return {
            value: new DataView(buffer.buffer).getFloat64(1, false),
            end: 9n
        };
    }

    if (info === 28 || info === 29 || info === 30) {
        throw new Error('Simple value is not well-formed');
    }

    if (info === 31) {
        throw new Error('break stop code is not supported in WebAuthn CBOR data');
    }

    throw new Error('Unexpected float type info value: ' + info);
}

function decodeDataItem(buffer: Uint8Array): { value: DecodedValue; end: bigint; } {
    assert(buffer.byteLength > 0, "Can't decode unknown data item from no data");
    const type = getType(buffer[0]!);

    switch (type) {
        case CBOR_TYPE_UNSIGNED_INT:
            return decodeUnsignedInt(buffer);
        case CBOR_TYPE_NEGATIVE_INT:
            return decodeNegativeInt(buffer);
        case CBOR_TYPE_BYTE_STRING:
            return decodeByteString(buffer);
        case CBOR_TYPE_TEXT_STRING:
            return decodeTextString(buffer);
        case CBOR_TYPE_ARRAY:
            return decodeArray(buffer);
        case CBOR_TYPE_MAP:
            return decodeMap(buffer);
        case CBOR_TYPE_TAG:
            return decodeTag(buffer);
        case CBOR_TYPE_FLOAT:
            return decodeFloat(buffer);
        default:
            throw new Error('Unknown CBOR type: ' + type);
    }
}

export function parseCBOR(buffer: Uint8Array): DecodedValue[] {
    let items = [];

    let offset = 0;
    while (offset < buffer.byteLength) {
        let { value: item, end } = decodeDataItem(buffer.subarray(offset));

        items.push(item);
        offset += Number(end);
    }

    return items;
}

export function parseAttestationObject(attestationObject: Uint8Array) {
    const items = parseCBOR(attestationObject);
    strictEqual(items.length, 1, 'Expected a single CBOR data item in the attestation object');

    const decoded = items[0];
    assert(decoded instanceof Map, 'Expected attestation object CBOR to hold a map');

    const fmt = decoded.get('fmt');
    assert(typeof fmt === 'string', 'Expected fmt to be a string');

    const attStmt = decoded.get('attStmt');
    assert(attStmt instanceof Map, 'Expected fmt to be a map');

    const authData = decoded.get('authData');
    assert(authData instanceof Uint8Array, 'Expected authData to be a Uint8Array');

    return { fmt, attStmt, authData };
}
