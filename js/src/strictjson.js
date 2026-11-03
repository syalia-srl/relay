/**
 * JSON parsing and field checks that PROTOCOL.md §1 requires: no duplicate key,
 * and an integer field only as a JSON number with no fraction or exponent in
 * 0 .. 2^53 - 1.
 */

const MAX_INTEGER = 2 ** 53 - 1;
const B64URL = /^[A-Za-z0-9_-]*$/;
const HEX64 = /^[0-9a-f]{64}$/;

export function isInteger(value) {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

export function isHex64(value) {
  return typeof value === "string" && HEX64.test(value);
}

export function isB64Url(value, length) {
  return typeof value === "string" && value.length === length && B64URL.test(value);
}

/**
 * JSON.parse, but refusing a duplicate key anywhere in the tree and keeping the
 * distinction between 3 and 3.0 that section 1 turns on. A number that is not a
 * plain integer comes back boxed, so isInteger refuses it while an unknown field
 * that holds one is still ignored.
 */
export function parse(text) {
  let index = 0;

  const fail = (why) => {
    throw new SyntaxError(why);
  };

  const skipWhitespace = () => {
    while (index < text.length && " \t\n\r".includes(text[index])) index++;
  };

  const parseString = () => {
    if (text[index] !== '"') fail("expected a string");
    index++;
    let out = "";
    let start = index;
    while (index < text.length) {
      const char = text[index];
      if (char === '"') {
        out += text.slice(start, index);
        index++;
        return out;
      }
      if (char < " ") fail("a control character in a string");
      if (char !== "\\") {
        index++;
        continue;
      }
      out += text.slice(start, index);
      index++;
      const escape = text[index++];
      const simple = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
      if (escape in simple) {
        out += simple[escape];
      } else if (escape === "u") {
        const digits = text.slice(index, index + 4);
        if (!/^[0-9a-fA-F]{4}$/.test(digits)) fail("a bad unicode escape");
        out += String.fromCharCode(Number.parseInt(digits, 16));
        index += 4;
      } else {
        fail("a bad escape");
      }
      start = index;
    }
    return fail("unterminated string");
  };

  const parseNumber = () => {
    const match = /^-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(text.slice(index));
    if (match === null) fail("expected a value");
    index += match[0].length;
    const value = Number(match[0]);
    if (match[1] !== undefined || match[2] !== undefined) return Object(value);
    // A long integer would round to a safe integer, so compare the lexeme itself.
    if (BigInt(match[0]) > BigInt(MAX_INTEGER)) return Object(value);
    return value;
  };

  const parseValue = () => {
    skipWhitespace();
    const char = text[index];
    if (char === "{") {
      index++;
      // A null prototype keeps a "__proto__" key from reaching an object's prototype.
      const object = Object.create(null);
      skipWhitespace();
      if (text[index] === "}") {
        index++;
        return object;
      }
      while (true) {
        skipWhitespace();
        const key = parseString();
        if (Object.prototype.hasOwnProperty.call(object, key)) fail("duplicate key");
        skipWhitespace();
        if (text[index] !== ":") fail("expected a colon");
        index++;
        object[key] = parseValue();
        skipWhitespace();
        if (text[index] === ",") {
          index++;
          continue;
        }
        if (text[index] === "}") {
          index++;
          return object;
        }
        return fail("expected a comma or brace");
      }
    }
    if (char === "[") {
      index++;
      const array = [];
      skipWhitespace();
      if (text[index] === "]") {
        index++;
        return array;
      }
      while (true) {
        array.push(parseValue());
        skipWhitespace();
        if (text[index] === ",") {
          index++;
          continue;
        }
        if (text[index] === "]") {
          index++;
          return array;
        }
        return fail("expected a comma or bracket");
      }
    }
    if (char === '"') return parseString();
    if (text.startsWith("true", index)) {
      index += 4;
      return true;
    }
    if (text.startsWith("false", index)) {
      index += 5;
      return false;
    }
    if (text.startsWith("null", index)) {
      index += 4;
      return null;
    }
    return parseNumber();
  };

  const value = parseValue();
  skipWhitespace();
  if (index !== text.length) fail("trailing text");
  return value;
}
