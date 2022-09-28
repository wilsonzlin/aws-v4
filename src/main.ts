import assertState from "@xtjs/lib/js/assertState";
import encodeUtf8 from "@xtjs/lib/js/encodeUtf8";
import map from "@xtjs/lib/js/map";
import { createHash, createHmac } from "crypto";

const sha256 = (bytes?: Uint8Array) => {
  const hasher = createHash("sha256");
  if (bytes) {
    hasher.update(bytes);
  }
  return hasher.digest();
};

const hmacSha256 = ({ data, secret }: { data: string; secret: Uint8Array }) => {
  const hmacer = createHmac("sha256", secret);
  hmacer.update(data);
  return hmacer.digest();
};

export const EMPTY_SHA256 = sha256().toString("hex").toLowerCase();

const VALID_PERCENT_ENCODING_BYTES = new Set(
  map(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
      "abcdefghijklmnopqrstuvwxyz" +
      "0123456789" +
      "_-~.",
    (c) => c.charCodeAt(0)
  )
);

// AWS's implementation.
export const awsPercentEncodeBytes = (str: string, encodeSlashes = true) =>
  [...encodeUtf8(str)]
    .map((b) => {
      if (
        VALID_PERCENT_ENCODING_BYTES.has(b) ||
        (b === 0x2f && !encodeSlashes)
      ) {
        return String.fromCharCode(b);
      }
      return "%" + b.toString(16).toUpperCase();
    })
    .join("");

const generateCanonicalRequest = ({
  method,
  host,
  path,
  queryArgs,
  headers,
  body,
  payloadSha256,
}: {
  method: string;
  host: string;
  // Must already be awsPercentEncodeBytes encoded.
  path: string;
  queryArgs?: { [name: string]: string | true };
  // Header names must be lowercase.
  headers?: { [name: string]: string };
  body?: Uint8Array;
  // If provided, will be used as hashed value of the payload.
  // If not provided, will use the "x-amz-content-sha256" header if provided. Otherwise, the body will be hashed.
  payloadSha256?: string;
}) => {
  const actualHeaders: {
    [name: string]: string;
  } = {
    host,
    ...(headers ?? {}),
  };

  payloadSha256 ??= actualHeaders["x-amz-content-sha256"] ??= sha256(body)
    .toString("hex")
    .toLowerCase();

  const signedHeaders = Object.keys(actualHeaders).sort().join(";");

  const c14nReq = [
    method,
    path,
    !queryArgs
      ? ""
      : Object.entries(queryArgs)
          .map(([name, value]) =>
            value === true
              ? `${awsPercentEncodeBytes(name)}`
              : `${awsPercentEncodeBytes(name)}=${awsPercentEncodeBytes(value)}`
          )
          .sort()
          .join("&"),
    ...Object.entries(actualHeaders)
      .map(([name, value]) => `${name}:${value.replace(/  +/g, " ").trim()}`)
      .sort(),
    "",
    signedHeaders,
    payloadSha256,
  ].join("\n");

  const reqHash = sha256(encodeUtf8(c14nReq));

  return {
    request: c14nReq,
    hash: reqHash.toString("hex").toLowerCase(),
    signedHeaders,
  };
};

const deriveSigningKey = ({
  secretAccessKey,
  region,
  service,
  isoDate,
}: {
  secretAccessKey: string;
  region: string;
  service: string;
  isoDate: string;
}) => {
  const dateKey = hmacSha256({
    secret: encodeUtf8(`AWS4${secretAccessKey}`),
    data: isoDate,
  });
  const dateRegionKey = hmacSha256({ secret: dateKey, data: region });
  const dateRegionServiceKey = hmacSha256({
    secret: dateRegionKey,
    data: service,
  });
  const signingKey = hmacSha256({
    secret: dateRegionServiceKey,
    data: "aws4_request",
  });

  return signingKey;
};

const sign = (derivedKey: Uint8Array, stringToSign: string) =>
  hmacSha256({ data: stringToSign, secret: derivedKey }).toString("hex");

const getIsoDateStringParts = (d: Date) => {
  const [_, year, month, day, hour, minute, second] =
    /^(\d+)-(\d+)-(\d+)T(\d+):(\d+):(\d+)\.\d+Z$/.exec(d.toISOString())!;
  return { year, month, day, hour, minute, second };
};

export class SignatureV4 {
  private readonly isoDate: string;
  private readonly isoDateTime: string;

  public constructor(
    private readonly httpRequest: {
      timestamp: Date;
      expires?: Date;
      method: string;
      host: string;
      // Must already be awsPercentEncodeBytes encoded.
      path: string;
      queryArgs?: { [name: string]: string | true };
      // Header names must be lowercase, so we can quickly look up header values.
      headers?: { [name: string]: string };
      body?: Uint8Array;
      payloadSha256?: string;
      service: string;
      region: string;
      accessKeyId: string;
      secretAccessKey: string;
    }
  ) {
    assertState(
      Object.keys(httpRequest.headers ?? {}).every((n) => n.toLowerCase() === n)
    );
    const { year, month, day, hour, minute, second } = getIsoDateStringParts(
      httpRequest.timestamp
    );
    this.isoDate = [year, month, day].join("");
    this.isoDateTime =
      httpRequest.headers?.["x-amz-date"] ??
      httpRequest.headers?.["date"] ??
      [year, month, day, "T", hour, minute, second, "Z"].join("");
  }

  toAuthHeader() {
    const { accessKeyId, secretAccessKey, region, service } = this.httpRequest;
    const c14nReq = generateCanonicalRequest(this.httpRequest);
    const { isoDate, isoDateTime } = this;
    const stringToSign = [
      "AWS4-HMAC-SHA256",
      isoDateTime,
      [isoDate, region, service, "aws4_request"].join("/"),
      c14nReq.hash,
    ].join("\n");
    const derivedKey = deriveSigningKey({
      secretAccessKey,
      region,
      service,
      isoDate,
    });
    const signature = sign(derivedKey, stringToSign);
    const headerValue =
      "AWS4-HMAC-SHA256 " +
      [
        `Credential=${accessKeyId}/${isoDate}/${region}/${service}/aws4_request`,
        `SignedHeaders=${c14nReq.signedHeaders}`,
        `Signature=${signature}`,
      ].join(", ");
    return headerValue;
  }

  /*
    There are several characteristics of requests made by a URL to keep in mind:

    - They cannot have body data
    - They always use the GET method
    - They cannot add, edit or remove any headers to/on/from the ones the client wishes to send
  */
  toQueryArgs() {
    const { isoDate, isoDateTime } = this;
    const {
      method,
      headers,
      body,
      queryArgs,
      secretAccessKey,
      timestamp,
      accessKeyId,
      region,
      service,
      expires,
      host,
      path,
      payloadSha256,
    } = this.httpRequest;
    if (method !== "GET") {
      throw new TypeError(
        "Cannot generate query string signature for non-GET request"
      );
    }

    if (headers || body) {
      throw new Error(
        "Headers and bodies are not allowed for query string signatures"
      );
    }

    const ts = getIsoDateStringParts(timestamp);
    const authQueryArgs: {
      [name: string]: string;
    } = {
      "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
      "X-Amz-Credential": [
        accessKeyId,
        [ts.year, ts.month, ts.day].join(""),
        region,
        service,
        "aws4_request",
      ].join("/"),
      "X-Amz-Date": isoDate,
      "X-Amz-SignedHeaders": "host",
    };
    if (expires) {
      authQueryArgs["X-Amz-Expires"] = Math.floor(
        (expires.getTime() - Date.now()) / 1000
      ).toString();
    }

    const canonicalRequest = generateCanonicalRequest({
      method,
      host,
      path,
      queryArgs: {
        ...queryArgs,
        ...authQueryArgs,
      },
      payloadSha256,
    });

    const stringToSign = [
      "AWS4-HMAC-SHA256",
      isoDateTime,
      [isoDate, region, service, "aws4_request"].join("/"),
      canonicalRequest.hash,
    ].join("\n");

    const derivedKey = deriveSigningKey({
      secretAccessKey,
      region,
      service,
      isoDate,
    });

    const signature = sign(derivedKey, stringToSign);
    authQueryArgs["X-Amz-Signature"] = signature;

    return authQueryArgs;
  }
}
