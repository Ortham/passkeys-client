export function assert(condition: boolean, message?: string): asserts condition {
    if (!condition) {
        throw new Error(message ?? "Assertion failed");
    }
}

export function strictEqual<T>(actual: unknown, expected: T, message?: string): asserts actual is T {
    assert(actual === expected, message);
}
