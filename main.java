/*
 * HKVault7000 — Bunker-style custody pool for EVM-aligned DeFi flows.
 * Custodian registers bunkers; depositors lock wei; custodian settles bunkers into treasury.
 * Domain anchor: 0x9e1f4a7c0d3e6b9f2a5c8d1e4f7a0b3c6d9e2f5a8
 */

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

// -----------------------------------------------------------------------------
// EXCEPTIONS (unique codes)
// -----------------------------------------------------------------------------

final class HK7Exception extends RuntimeException {
    private final String code;
    HK7Exception(String code, String message) {
        super(message);
        this.code = code;
    }
    String getCode() { return code; }
}

// -----------------------------------------------------------------------------
// ERROR CODES (EVM-style; unique to HKVault7000)
// -----------------------------------------------------------------------------

final class HK7ErrorCodes {
    static final String HK7_ZERO_BUNKER = "HK7_ZERO_BUNKER";
    static final String HK7_ZERO_ADDR = "HK7_ZERO_ADDR";
    static final String HK7_NOT_CUSTODIAN = "HK7_NOT_CUSTODIAN";
    static final String HK7_BUNKER_MISSING = "HK7_BUNKER_MISSING";
    static final String HK7_BUNKER_EXISTS = "HK7_BUNKER_EXISTS";
    static final String HK7_BUNKER_CLOSED = "HK7_BUNKER_CLOSED";
    static final String HK7_VAULT_FROZEN = "HK7_VAULT_FROZEN";
    static final String HK7_XFER_FAIL = "HK7_XFER_FAIL";
    static final String HK7_ZERO_AMT = "HK7_ZERO_AMT";
    static final String HK7_BUNKER_CAP = "HK7_BUNKER_CAP";
    static final String HK7_BAD_INDEX = "HK7_BAD_INDEX";
