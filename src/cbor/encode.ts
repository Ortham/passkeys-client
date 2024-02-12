// https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-conforming-all-classes
// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ctap2-canonical-cbor-encoding-form
// https://www.rfc-editor.org/rfc/rfc8949.html

import { assert } from "../assert";
import { CBOR_TYPE_ARRAY, CBOR_TYPE_BYTE_STRING, CBOR_TYPE_FLOAT, CBOR_TYPE_MAP, CBOR_TYPE_NEGATIVE_INT, CBOR_TYPE_TEXT_STRING, CBOR_TYPE_UNSIGNED_INT } from "./common";

export function concatArrays(...arrays: Uint8Array[]): Uint8Array {
    const length = arrays.map(a => a.byteLength).reduce((prev, curr) => prev + curr, 0);
    const array = new Uint8Array(length);

    let offset = 0;
    for (const arr of arrays) {
        array.set(arr, offset);
        offset += arr.byteLength;
    }

    return array;
}

function lexicographicalCompare(lhs: Uint8Array, rhs: Uint8Array): number {
    let i = 0;
    while (i < lhs.byteLength && i < rhs.byteLength) {
        const left = lhs[i];
        const right = rhs[i];
        assert(left !== undefined);
        assert(right !== undefined);
        if (left < right) {
            return -1;
        } else if (right < left) {
            return 1;
        }

        i += 1;
    }

    if (lhs.byteLength < rhs.byteLength) {
        return -1;
    } else if (rhs.byteLength < lhs.byteLength) {
        return 1;
    }

    return 0;
}

function getTypeBits(cborType: number): number {
    return cborType << 5;
}

function encodeDataLength(length: number): Uint8Array {
    if (length < 24) {
        return new Uint8Array([length]);
    } else if (length < 256) {
        return new Uint8Array([24, length]);
    } else if (length < 65536) {
        return new Uint8Array([25, (length & 0xFF00) >> 8, length & 0x00FF]);
    } else if (length < 4294967296) {
        return new Uint8Array([
            26,
            (length & 0xFF00_0000) >> 24,
            (length & 0x00FF_0000) >> 16,
            (length & 0x0000_FF00) >> 8,
            (length & 0x0000_00FF),
        ]);
    } else {
        throw new Error('Lengths larger than 4 GB are not supported');
    }
}

function encodeUnsignedInt(data: number): Uint8Array {
    const array = encodeDataLength(data);
    array[0] |= getTypeBits(CBOR_TYPE_UNSIGNED_INT);

    return array;
}

function encodeNegativeInt(data: number): Uint8Array {
    const argumentValue = -1 - data;
    const array = encodeDataLength(argumentValue);
    array[0] |= getTypeBits(CBOR_TYPE_NEGATIVE_INT);

    return array;
}

function encodeFloat64(data: number): Uint8Array {
    const array = new Uint8Array(9);
    array[0] = getTypeBits(CBOR_TYPE_FLOAT) | 27;

    new DataView(array.buffer).setFloat64(1, data, false);

    return array;
}

function encodeNumber(data: number): Uint8Array {
    if (Number.isInteger(data)) {
        if (data > -1) {
            return encodeUnsignedInt(data);
        }

        return encodeNegativeInt(data);
    } else {
        // All (non-bigint) numbers in JS are float64.
        return encodeFloat64(data);
    }
}

function encodeArrayBuffer(data: ArrayBuffer | Uint8Array): Uint8Array {
    const lengthBuffer = encodeDataLength(data.byteLength);
    lengthBuffer[0] |= getTypeBits(CBOR_TYPE_BYTE_STRING);

    return concatArrays(lengthBuffer, new Uint8Array(data));
}

function encodeString(data: string): Uint8Array {
    const utf8String = new TextEncoder().encode(data);

    const lengthBuffer = encodeDataLength(utf8String.byteLength);
    lengthBuffer[0] |= getTypeBits(CBOR_TYPE_TEXT_STRING);

    return concatArrays(lengthBuffer, utf8String);
}

function encodeArray(data: unknown[]): Uint8Array {
    const lengthBuffer = encodeDataLength(data.length);
    lengthBuffer[0] |= getTypeBits(CBOR_TYPE_ARRAY);

    const arrays = [lengthBuffer];

    for (const element of data) {
        const encoded = encodeDataItem(element);
        arrays.push(encoded);
    }

    return concatArrays(...arrays);
}

export function encodeMap(map: Map<string, unknown>): Uint8Array {
    const lengthBuffer = encodeDataLength(map.size);
    lengthBuffer[0] |= getTypeBits(CBOR_TYPE_MAP);

    const encodedEntries = [];
    for (const [key, value] of map.entries()) {
        const encodedKey = encodeDataItem(key);
        const encodedValue = encodeDataItem(value);

        encodedEntries.push([encodedKey, encodedValue]);
    }

    // Sort based on the bytewise lexicographic order of the encoded keys.
    encodedEntries.sort(([lhs,], [rhs,]) => {
        assert(lhs !== undefined);
        assert(rhs !== undefined);

        return lexicographicalCompare(lhs, rhs);
    });

    // Now flatten into a single array.
    const arrays = encodedEntries.flat(1);

    return concatArrays(lengthBuffer, ...arrays);
}

function encodeBoolean(data: boolean): Uint8Array {
    const array = new Uint8Array(1);
    const encodedValue = data ? 21 : 20;
    array[0] = getTypeBits(CBOR_TYPE_FLOAT) | encodedValue;

    return array;
}

function encodeNull(): Uint8Array {
    const array = new Uint8Array(1);
    array[0] = getTypeBits(CBOR_TYPE_FLOAT) | 22;

    return array;
}

function encodeUndefined(): Uint8Array {
    const array = new Uint8Array(1);
    array[0] = getTypeBits(CBOR_TYPE_FLOAT) | 23;

    return array;
}

function encodeDataItem(data: unknown): Uint8Array {
    if (typeof data === 'number') {
        return encodeNumber(data);
    } else if (data instanceof ArrayBuffer || data instanceof Uint8Array) {
        return encodeArrayBuffer(data);
    } else if (typeof data === 'string') {
        return encodeString(data);
    } else if (Array.isArray(data)) {
        return encodeArray(data);
    } else if (data instanceof Map) {
        return encodeMap(data);
    } else if (data === null) {
        return encodeNull();
    } else if (data === undefined) {
        return encodeUndefined();
    } else if (typeof data === 'boolean') {
        return encodeBoolean(data);
    } else if (typeof data === 'object') {
        return encodeMap(new Map(Object.entries(data)));
    } else {
        throw new Error('Unsupported data type: ' + data);
    }
}
