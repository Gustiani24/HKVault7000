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
    static final String HK7_INTEGRITY = "HK7_INTEGRITY";

    static String describe(String code) {
        if (code == null) return "Unknown";
        switch (code) {
            case HK7_ZERO_BUNKER: return "Bunker id is zero or empty";
            case HK7_ZERO_ADDR: return "Custodian or treasury address invalid";
            case HK7_NOT_CUSTODIAN: return "Caller is not custodian";
            case HK7_BUNKER_MISSING: return "Bunker not found";
            case HK7_BUNKER_EXISTS: return "Bunker already exists";
            case HK7_BUNKER_CLOSED: return "Bunker already settled";
            case HK7_VAULT_FROZEN: return "Vault is frozen";
            case HK7_XFER_FAIL: return "Transfer failed";
            case HK7_ZERO_AMT: return "Deposit amount must be positive or below min / above max";
            case HK7_BUNKER_CAP: return "Bunker or global deposit cap exceeded";
            case HK7_BAD_INDEX: return "Index out of range";
            case HK7_INTEGRITY: return "Integrity check failed";
            default: return "Unknown error: " + code;
        }
    }

    static List<String> allCodes() {
        return List.of(HK7_ZERO_BUNKER, HK7_ZERO_ADDR, HK7_NOT_CUSTODIAN, HK7_BUNKER_MISSING, HK7_BUNKER_EXISTS,
            HK7_BUNKER_CLOSED, HK7_VAULT_FROZEN, HK7_XFER_FAIL, HK7_ZERO_AMT, HK7_BUNKER_CAP, HK7_BAD_INDEX, HK7_INTEGRITY);
    }
}

// -----------------------------------------------------------------------------
// WEI SAFE MATH (overflow-safe for EVM-style amounts)
// -----------------------------------------------------------------------------

final class HK7WeiMath {
    private static final BigInteger MAX_U256 = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);

    static BigInteger clampU256(BigInteger value) {
        if (value == null || value.signum() < 0) return BigInteger.ZERO;
        if (value.compareTo(MAX_U256) > 0) return MAX_U256;
        return value;
    }

    static BigInteger addSafe(BigInteger a, BigInteger b) {
        BigInteger sum = (a == null ? BigInteger.ZERO : a).add(b == null ? BigInteger.ZERO : b);
        return clampU256(sum);
    }

    static BigInteger subSafe(BigInteger a, BigInteger b) {
        BigInteger aa = a == null ? BigInteger.ZERO : a;
        BigInteger bb = b == null ? BigInteger.ZERO : b;
        if (bb.compareTo(aa) > 0) return BigInteger.ZERO;
        return aa.subtract(bb);
    }

    static boolean isZeroOrNegative(BigInteger v) {
        return v == null || v.signum() <= 0;
    }
}

// -----------------------------------------------------------------------------
// EVM-STYLE ADDRESS VALIDATION
// -----------------------------------------------------------------------------

final class HK7AddressValidator {
    private static final Pattern EVM_ADDRESS = Pattern.compile("^0x[a-fA-F0-9]{40}$");

    static boolean isValid(String address) {
        return address != null && EVM_ADDRESS.matcher(address.trim()).matches();
    }

    static String normalize(String address) {
        if (address == null) return null;
        String s = address.trim();
        return s.toLowerCase().startsWith("0x") ? s : "0x" + s;
    }
}

// -----------------------------------------------------------------------------
// FEE CALCULATOR (immutable basis points; EVM-safe)
// -----------------------------------------------------------------------------

final class HK7FeeCalculator {
    private static final int BPS_MAX = 10_000;
    private final int feeBps;

    HK7FeeCalculator(int feeBps) {
        this.feeBps = Math.max(0, Math.min(feeBps, BPS_MAX));
    }

    BigInteger computeFee(BigInteger amountWei) {
        if (amountWei == null || amountWei.signum() <= 0 || feeBps == 0) return BigInteger.ZERO;
        return amountWei.multiply(BigInteger.valueOf(feeBps)).divide(BigInteger.valueOf(BPS_MAX));
    }

    BigInteger amountAfterFee(BigInteger amountWei) {
        return HK7WeiMath.subSafe(amountWei == null ? BigInteger.ZERO : amountWei, computeFee(amountWei));
    }

    int getFeeBps() { return feeBps; }
}

// -----------------------------------------------------------------------------
// QUOTA MANAGER (per-bunker and global caps)
// -----------------------------------------------------------------------------

final class HK7QuotaManager {
    private final BigInteger globalDepositCap;
    private final BigInteger defaultBunkerCap;
    private final Map<String, BigInteger> bunkerCaps = new ConcurrentHashMap<>();

    HK7QuotaManager(BigInteger globalDepositCap, BigInteger defaultBunkerCap) {
        this.globalDepositCap = globalDepositCap == null || globalDepositCap.signum() < 0 ? BigInteger.ZERO : globalDepositCap;
        this.defaultBunkerCap = defaultBunkerCap == null || defaultBunkerCap.signum() < 0 ? BigInteger.ZERO : defaultBunkerCap;
    }

    void setBunkerCap(String bunkerId, BigInteger cap) {
        if (bunkerId != null) bunkerCaps.put(bunkerId, cap == null ? defaultBunkerCap : cap);
    }

    BigInteger getBunkerCap(String bunkerId) {
        return bunkerCaps.getOrDefault(bunkerId, defaultBunkerCap);
    }

    boolean wouldExceedBunkerCap(String bunkerId, BigInteger currentBalance, BigInteger addAmount) {
        BigInteger cap = getBunkerCap(bunkerId);
        if (cap.signum() == 0) return false;
        BigInteger next = (currentBalance == null ? BigInteger.ZERO : currentBalance).add(addAmount == null ? BigInteger.ZERO : addAmount);
        return next.compareTo(cap) > 0;
    }

    boolean wouldExceedGlobalCap(BigInteger currentTotal, BigInteger addAmount) {
        if (globalDepositCap.signum() == 0) return false;
        BigInteger next = (currentTotal == null ? BigInteger.ZERO : currentTotal).add(addAmount == null ? BigInteger.ZERO : addAmount);
        return next.compareTo(globalDepositCap) > 0;
    }

    BigInteger getGlobalDepositCap() { return globalDepositCap; }
    BigInteger getDefaultBunkerCap() { return defaultBunkerCap; }
}

// -----------------------------------------------------------------------------
// DEPOSIT LEDGER (depositor -> amount per bunker; for accounting)
// -----------------------------------------------------------------------------

final class HK7DepositLedger {
    private final Map<String, Map<String, BigInteger>> bunkerDeposits = new ConcurrentHashMap<>();

    void recordDeposit(String bunkerId, String depositor, BigInteger amountWei) {
        if (bunkerId == null || amountWei == null || amountWei.signum() <= 0) return;
