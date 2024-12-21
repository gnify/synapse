// https://github.com/fastify/secure-json-parse
// https://github.com/hapijs/bourne

const suspectProtoRx =
  /"(?:_|\\u0{2}5[Ff]){2}(?:p|\\u0{2}70)(?:r|\\u0{2}72)(?:o|\\u0{2}6[Ff])(?:t|\\u0{2}74)(?:o|\\u0{2}6[Ff])(?:_|\\u0{2}5[Ff]){2}"\s*:/;
const suspectConstructorRx =
  /"(?:c|\\u0063)(?:o|\\u006[Ff])(?:n|\\u006[Ee])(?:s|\\u0073)(?:t|\\u0074)(?:r|\\u0072)(?:u|\\u0075)(?:c|\\u0063)(?:t|\\u0074)(?:o|\\u006[Ff])(?:r|\\u0072)"\s*:/;

const leadingDigitRegex = /^\s*-?\d/;

export type Options = {
  strict?: boolean;
};

const KNOWN_VALUES = new Map<string, boolean | null | undefined | number>([
  ["true", true],
  ["false", false],
  ["null", undefined],
  ["undefined", undefined],
  ["NaN", Number.NaN],
  ["Infinity", Number.POSITIVE_INFINITY],
  ["-Infinity", Number.NEGATIVE_INFINITY],
]);

const BIGINT_REGEX = /^-?\d+n$/i;

export function synapse<T = unknown>(value: any, options: Options = {}): T {
  if (typeof value !== "string") {
    return value;
  }

  const _value = value.trim();
  const len = _value.length;

  if (len <= 10) {
    const knownValue = KNOWN_VALUES.get(_value);
    if (knownValue !== undefined) {
      return knownValue as T;
    }
  }

  if (len === 2 && _value.codePointAt(0) === 34 /* " */) {
    return "" as T;
  }

  if (
    _value.codePointAt(0) === 34 /* " */ &&
    _value.codePointAt(len - 1) === 34 /* " */
  ) {
    return _value.slice(1, -1) as T;
  }

  if (BIGINT_REGEX.test(_value)) {
    try {
      return BigInt(_value.slice(0, -1)) as T;
    } catch {
      if (options.strict) {
        throw new SyntaxError(`[synapse] Invalid BigInt: ${_value}`);
      }
      return value as T;
    }
  }

  const firstChar = _value.codePointAt(0);

  if (
    firstChar === 91 /* [ */ ||
    firstChar === 123 /* { */ ||
    firstChar === 34 /* " */ ||
    leadingDigitRegex.test(_value)
  ) {
    try {
      if (
        options.strict &&
        (suspectProtoRx.test(value) || suspectConstructorRx.test(value))
      ) {
        throw new Error("[synapse] Possible prototype pollution");
      }
      return JSON.parse(value) as T;
    } catch (error) {
      if (options.strict) {
        throw error;
      }
      return value as T;
    }
  }

  if (options.strict) {
    throw new SyntaxError("[synapse] Invalid JSON");
  }
  return value as T;
}

export function safesynapse<T = unknown>(value: any, options: Options = {}): T {
  return synapse<T>(value, { ...options, strict: true });
}

export default synapse;
