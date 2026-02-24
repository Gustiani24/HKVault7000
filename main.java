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
        bunkerDeposits.computeIfAbsent(bunkerId, k -> new ConcurrentHashMap<>())
            .merge(depositor != null ? depositor : "0x0000000000000000000000000000000000000000", amountWei, HK7WeiMath::addSafe);
    }

    BigInteger getDepositBy(String bunkerId, String depositor) {
        Map<String, BigInteger> m = bunkerDeposits.get(bunkerId);
        return m == null ? BigInteger.ZERO : m.getOrDefault(depositor, BigInteger.ZERO);
    }

    int getDepositorCount(String bunkerId) {
        Map<String, BigInteger> m = bunkerDeposits.get(bunkerId);
        return m == null ? 0 : m.size();
    }

    Set<String> getDepositors(String bunkerId) {
        Map<String, BigInteger> m = bunkerDeposits.get(bunkerId);
        return m == null ? Set.of() : Collections.unmodifiableSet(new HashSet<>(m.keySet()));
    }

    Map<String, BigInteger> getBunkerDepositsSnapshot(String bunkerId) {
        Map<String, BigInteger> m = bunkerDeposits.get(bunkerId);
        return m == null ? Map.of() : new HashMap<>(m);
    }
}

// -----------------------------------------------------------------------------
// AUDIT LOG (append-only entries)
// -----------------------------------------------------------------------------

final class HK7AuditEntry {
    private final long timestamp;
    private final String action;
    private final String actor;
    private final String detail;

    HK7AuditEntry(long timestamp, String action, String actor, String detail) {
        this.timestamp = timestamp;
        this.action = action != null ? action : "";
        this.actor = actor != null ? actor : "";
        this.detail = detail != null ? detail : "";
    }

    public long getTimestamp() { return timestamp; }
    public String getAction() { return action; }
    public String getActor() { return actor; }
    public String getDetail() { return detail; }
}

final class HK7AuditLog {
    private static final int MAX_ENTRIES = 10_000;
    private final List<HK7AuditEntry> entries = Collections.synchronizedList(new ArrayList<>());

    void append(String action, String actor, String detail) {
        synchronized (entries) {
            entries.add(new HK7AuditEntry(System.currentTimeMillis() / 1000L, action, actor, detail));
            while (entries.size() > MAX_ENTRIES) entries.remove(0);
        }
    }

    List<HK7AuditEntry> getRecent(int n) {
        synchronized (entries) {
            int size = entries.size();
            if (n <= 0 || size == 0) return List.of();
            int from = Math.max(0, size - n);
            return new ArrayList<>(entries.subList(from, size));
        }
    }

    int size() { return entries.size(); }
}

// -----------------------------------------------------------------------------
// VAULT CONFIG (immutable after construction)
// -----------------------------------------------------------------------------

final class HK7VaultConfig {
    private final String chainIdHex;
    private final BigInteger minDepositWei;
    private final BigInteger maxDepositPerTxWei;
    private final int feeBps;
    private final String feeRecipientHex;

    HK7VaultConfig(String chainIdHex, BigInteger minDepositWei, BigInteger maxDepositPerTxWei, int feeBps, String feeRecipientHex) {
        this.chainIdHex = chainIdHex != null ? chainIdHex : "0x1";
        this.minDepositWei = minDepositWei == null || minDepositWei.signum() < 0 ? BigInteger.ZERO : minDepositWei;
        this.maxDepositPerTxWei = maxDepositPerTxWei == null || maxDepositPerTxWei.signum() < 0 ? BigInteger.ZERO : maxDepositPerTxWei;
        this.feeBps = Math.max(0, Math.min(feeBps, 10_000));
        this.feeRecipientHex = feeRecipientHex != null ? feeRecipientHex : "0x0000000000000000000000000000000000000000";
    }

    public String getChainIdHex() { return chainIdHex; }
    public BigInteger getMinDepositWei() { return minDepositWei; }
    public BigInteger getMaxDepositPerTxWei() { return maxDepositPerTxWei; }
    public int getFeeBps() { return feeBps; }
    public String getFeeRecipientHex() { return feeRecipientHex; }
}

// -----------------------------------------------------------------------------
// EVENTS (immutable payloads)
// -----------------------------------------------------------------------------

final class HK7BunkerRegistered {
    private final String bunkerId;
    private final String tagHash;
    private final long atBlock;
    HK7BunkerRegistered(String bunkerId, String tagHash, long atBlock) {
        this.bunkerId = bunkerId;
        this.tagHash = tagHash;
        this.atBlock = atBlock;
    }
    public String getBunkerId() { return bunkerId; }
    public String getTagHash() { return tagHash; }
    public long getAtBlock() { return atBlock; }
}

final class HK7Deposited {
    private final String bunkerId;
    private final String from;
    private final BigInteger amountWei;
    private final long atBlock;
    HK7Deposited(String bunkerId, String from, BigInteger amountWei, long atBlock) {
        this.bunkerId = bunkerId;
        this.from = from;
        this.amountWei = amountWei;
        this.atBlock = atBlock;
    }
    public String getBunkerId() { return bunkerId; }
    public String getFrom() { return from; }
    public BigInteger getAmountWei() { return amountWei; }
    public long getAtBlock() { return atBlock; }
}

final class HK7BunkerSettled {
    private final String bunkerId;
    private final BigInteger amountWei;
    private final long atBlock;
    HK7BunkerSettled(String bunkerId, BigInteger amountWei, long atBlock) {
        this.bunkerId = bunkerId;
        this.amountWei = amountWei;
        this.atBlock = atBlock;
    }
    public String getBunkerId() { return bunkerId; }
    public BigInteger getAmountWei() { return amountWei; }
    public long getAtBlock() { return atBlock; }
}

final class HK7TreasuryCredited {
    private final String treasury;
    private final BigInteger amountWei;
    private final long atBlock;
    HK7TreasuryCredited(String treasury, BigInteger amountWei, long atBlock) {
        this.treasury = treasury;
        this.amountWei = amountWei;
        this.atBlock = atBlock;
    }
    public String getTreasury() { return treasury; }
    public BigInteger getAmountWei() { return amountWei; }
    public long getAtBlock() { return atBlock; }
}

final class HK7VaultFrozen {
    private final String by;
    private final long atBlock;
    HK7VaultFrozen(String by, long atBlock) { this.by = by; this.atBlock = atBlock; }
    public String getBy() { return by; }
    public long getAtBlock() { return atBlock; }
}

final class HK7VaultThawed {
    private final String by;
    private final long atBlock;
    HK7VaultThawed(String by, long atBlock) { this.by = by; this.atBlock = atBlock; }
    public String getBy() { return by; }
    public long getAtBlock() { return atBlock; }
}

// -----------------------------------------------------------------------------
// BUNKER INFO (immutable view)
// -----------------------------------------------------------------------------

final class HK7BunkerInfo {
    private final String bunkerId;
    private final String tagHash;
    private final BigInteger balance;
    private final long createdAtBlock;
    private final boolean settled;

    HK7BunkerInfo(String bunkerId, String tagHash, BigInteger balance, long createdAtBlock, boolean settled) {
        this.bunkerId = bunkerId;
        this.tagHash = tagHash;
        this.balance = balance == null ? BigInteger.ZERO : balance;
        this.createdAtBlock = createdAtBlock;
        this.settled = settled;
    }

    public String getBunkerId() { return bunkerId; }
    public String getTagHash() { return tagHash; }
    public BigInteger getBalance() { return balance; }
    public long getCreatedAtBlock() { return createdAtBlock; }
    public boolean isSettled() { return settled; }
}

// -----------------------------------------------------------------------------
// EVENT LISTENER INTERFACE
// -----------------------------------------------------------------------------

interface HK7EventListener {
    void onBunkerRegistered(HK7BunkerRegistered e);
    void onDeposited(HK7Deposited e);
    void onBunkerSettled(HK7BunkerSettled e);
    void onTreasuryCredited(HK7TreasuryCredited e);
    void onVaultFrozen(HK7VaultFrozen e);
    void onVaultThawed(HK7VaultThawed e);
}

// -----------------------------------------------------------------------------
// BUNKER STATS (aggregate view for one bunker)
// -----------------------------------------------------------------------------

final class HK7BunkerStats {
    private final String bunkerId;
    private final BigInteger balance;
    private final int depositorCount;
    private final boolean settled;
    private final long createdAtBlock;

    HK7BunkerStats(String bunkerId, BigInteger balance, int depositorCount, boolean settled, long createdAtBlock) {
        this.bunkerId = bunkerId;
        this.balance = balance == null ? BigInteger.ZERO : balance;
        this.depositorCount = depositorCount;
        this.settled = settled;
        this.createdAtBlock = createdAtBlock;
    }

    public String getBunkerId() { return bunkerId; }
    public BigInteger getBalance() { return balance; }
    public int getDepositorCount() { return depositorCount; }
    public boolean isSettled() { return settled; }
    public long getCreatedAtBlock() { return createdAtBlock; }
}

// -----------------------------------------------------------------------------
// VAULT STATS (global aggregate)
// -----------------------------------------------------------------------------

final class HK7VaultStats {
    private final long bunkerCount;
    private final long activeBunkerCount;
    private final BigInteger totalDepositedWei;
    private final BigInteger totalSettledWei;
    private final BigInteger vaultTotalBalance;
    private final boolean frozen;
    private final long deployBlock;

    HK7VaultStats(long bunkerCount, long activeBunkerCount, BigInteger totalDepositedWei, BigInteger totalSettledWei,
                  BigInteger vaultTotalBalance, boolean frozen, long deployBlock) {
        this.bunkerCount = bunkerCount;
        this.activeBunkerCount = activeBunkerCount;
        this.totalDepositedWei = totalDepositedWei == null ? BigInteger.ZERO : totalDepositedWei;
        this.totalSettledWei = totalSettledWei == null ? BigInteger.ZERO : totalSettledWei;
        this.vaultTotalBalance = vaultTotalBalance == null ? BigInteger.ZERO : vaultTotalBalance;
        this.frozen = frozen;
        this.deployBlock = deployBlock;
    }

    public long getBunkerCount() { return bunkerCount; }
    public long getActiveBunkerCount() { return activeBunkerCount; }
    public BigInteger getTotalDepositedWei() { return totalDepositedWei; }
    public BigInteger getTotalSettledWei() { return totalSettledWei; }
    public BigInteger getVaultTotalBalance() { return vaultTotalBalance; }
    public boolean isFrozen() { return frozen; }
    public long getDeployBlock() { return deployBlock; }
}

// -----------------------------------------------------------------------------
// VAULT ENGINE (simulation and batch helpers; no mutable vault state)
// -----------------------------------------------------------------------------

final class HK7VaultEngine {
    private static final String ANCHOR = "0x9e1f4a7c0d3e6b9f2a5c8d1e4f7a0b3c6d9e2f5a8";

    static String getAnchor() { return ANCHOR; }

    /** Simulate whether a deposit would succeed given current balances and caps. */
    static boolean wouldDepositSucceed(BigInteger currentBunkerBalance, BigInteger currentGlobalDeposited,
                                       BigInteger bunkerCap, BigInteger globalCap, BigInteger amountWei,
                                       BigInteger minDeposit, BigInteger maxPerTx) {
        if (amountWei == null || amountWei.signum() <= 0) return false;
        if (minDeposit != null && minDeposit.signum() > 0 && amountWei.compareTo(minDeposit) < 0) return false;
        if (maxPerTx != null && maxPerTx.signum() > 0 && amountWei.compareTo(maxPerTx) > 0) return false;
        BigInteger b = currentBunkerBalance == null ? BigInteger.ZERO : currentBunkerBalance;
        if (bunkerCap != null && bunkerCap.signum() > 0 && b.add(amountWei).compareTo(bunkerCap) > 0) return false;
        BigInteger g = currentGlobalDeposited == null ? BigInteger.ZERO : currentGlobalDeposited;
        if (globalCap != null && globalCap.signum() > 0 && g.add(amountWei).compareTo(globalCap) > 0) return false;
        return true;
    }

    /** Project fee and net for a given amount and bps. */
    static BigInteger projectFee(BigInteger amountWei, int feeBps) {
        if (amountWei == null || amountWei.signum() <= 0 || feeBps <= 0) return BigInteger.ZERO;
        int bps = Math.max(0, Math.min(feeBps, 10_000));
        return amountWei.multiply(BigInteger.valueOf(bps)).divide(BigInteger.valueOf(10_000));
    }

    static BigInteger projectNetAfterFee(BigInteger amountWei, int feeBps) {
        return HK7WeiMath.subSafe(amountWei == null ? BigInteger.ZERO : amountWei, projectFee(amountWei, feeBps));
    }

    /** Validate bunker id format (non-empty, reasonable length). */
    static boolean isValidBunkerId(String bunkerId) {
        return bunkerId != null && !bunkerId.trim().isEmpty() && bunkerId.length() <= 128;
    }

    /** Validate tag hash format (optional hex). */
    static boolean isValidTagHash(String tagHash) {
        if (tagHash == null || tagHash.isEmpty()) return true;
        return tagHash.length() <= 66 && (tagHash.startsWith("0x") && tagHash.substring(2).matches("[a-fA-F0-9]+") || tagHash.matches("[a-fA-F0-9]+"));
    }

    /** Compute a deterministic hash-like id from seed (for testing). */
    static String deriveBunkerId(String seed, int index) {
        if (seed == null) seed = "";
        String s = seed + "_" + index;
        int h = s.hashCode();
        return "bunker-0x" + Integer.toHexString(h >= 0 ? h : (h & 0x7FFF_FFFF));
    }

    /** Batch derive bunker ids. */
    static List<String> deriveBunkerIds(String seed, int count) {
        List<String> out = new ArrayList<>(count);
        for (int i = 0; i < count; i++) out.add(deriveBunkerId(seed, i));
        return out;
    }
}

// -----------------------------------------------------------------------------
// STATE ENCODER (export vault summary for off-chain audit)
// -----------------------------------------------------------------------------

final class HK7StateEncoder {
    static String encodeSummary(HKVault7000 vault) {
        StringBuilder sb = new StringBuilder();
        sb.append("HK7|").append(HKVault7000.HK7_VERSION).append("|");
        sb.append("custodian=").append(vault.getCustodian()).append("|");
        sb.append("treasury=").append(vault.getTreasury()).append("|");
        sb.append("deployBlock=").append(vault.getDeployBlock()).append("|");
        sb.append("frozen=").append(vault.isFrozen()).append("|");
        sb.append("bunkerCount=").append(vault.getBunkerCount()).append("|");
        sb.append("totalDeposited=").append(vault.getTotalDepositedWei()).append("|");
        sb.append("totalSettled=").append(vault.getTotalSettledWei()).append("|");
        sb.append("namespace=").append(HKVault7000.HK7_NAMESPACE_HEX);
        return sb.toString();
    }

    static List<String> encodeBunkerLines(HKVault7000 vault) {
        List<String> out = new ArrayList<>();
        for (String id : vault.getAllBunkerIds()) {
            HK7BunkerInfo info = vault.getBunkerInfo(id);
            out.add(String.format("bunker|%s|%s|%s|%d|%s", id, info.getTagHash(), info.getBalance(), info.getCreatedAtBlock(), info.isSettled()));
        }
        return out;
    }
}

// -----------------------------------------------------------------------------
// STATE DECODER (parse summary line; no mutation)
// -----------------------------------------------------------------------------

final class HK7StateDecoder {
    static Map<String, String> decodeSummary(String line) {
        Map<String, String> m = new HashMap<>();
        if (line == null || !line.startsWith("HK7|")) return m;
        String[] parts = line.split("\\|");
        for (int i = 1; i < parts.length; i++) {
            String p = parts[i];
            int eq = p.indexOf('=');
            if (eq > 0) m.put(p.substring(0, eq), p.substring(eq + 1));
        }
        return m;
    }
}

// -----------------------------------------------------------------------------
// INTEGRITY CHECK (invariants for safe mainnet-style behavior)
// -----------------------------------------------------------------------------

final class HK7IntegrityCheck {
    /** Sum of active bunker balances must not exceed total deposited (no double-spend). */
    static boolean checkBalanceInvariant(HKVault7000 vault) {
        BigInteger active = vault.getVaultTotalBalance();
        BigInteger totalDep = vault.getTotalDepositedWei();
        BigInteger totalSet = vault.getTotalSettledWei();
        return active.add(totalSet).compareTo(totalDep) <= 0 && totalDep.compareTo(BigInteger.ZERO) >= 0;
    }

    /** Every bunker in list must exist and have consistent settled flag. */
    static boolean checkBunkerConsistency(HKVault7000 vault) {
        for (String id : vault.getAllBunkerIds()) {
            if (!vault.bunkerExists(id)) return false;
            HK7BunkerInfo info = vault.getBunkerInfo(id);
            if (vault.isBunkerSettled(id) != info.isSettled()) return false;
        }
        return true;
    }

    /** Custodian and treasury must be valid EVM addresses. */
    static boolean checkAddresses(HKVault7000 vault) {
        return HK7AddressValidator.isValid(vault.getCustodian()) && HK7AddressValidator.isValid(vault.getTreasury());
    }

    /** Run all checks; returns first failure message or null if ok. */
    static String runAllChecks(HKVault7000 vault) {
        if (!checkAddresses(vault)) return "HK7_CHECK: invalid custodian or treasury";
        if (!checkBalanceInvariant(vault)) return "HK7_CHECK: balance invariant violated";
        if (!checkBunkerConsistency(vault)) return "HK7_CHECK: bunker consistency failed";
        return null;
    }
}

// -----------------------------------------------------------------------------
// RUNBOOK (step-by-step procedures for ops; no state mutation)
// -----------------------------------------------------------------------------

final class HK7Runbook {
    static final int STEP_REGISTER = 1;
    static final int STEP_DEPOSIT = 2;
    static final int STEP_SETTLE = 3;
    static final int STEP_FREEZE = 4;
    static final int STEP_THAW = 5;
    static final int STEP_AUDIT = 6;

    static String describeStep(int step) {
        switch (step) {
            case STEP_REGISTER: return "Register bunker (custodian only)";
            case STEP_DEPOSIT: return "Deposit wei into bunker (anyone, when not frozen)";
            case STEP_SETTLE: return "Settle bunker and credit treasury (custodian only)";
            case STEP_FREEZE: return "Freeze vault (custodian only)";
            case STEP_THAW: return "Thaw vault (custodian only)";
            case STEP_AUDIT: return "Export audit / summary";
            default: return "Unknown step";
        }
    }

    static List<String> preconditionsForRegister(HKVault7000 vault) {
        List<String> out = new ArrayList<>();
        if (vault.isFrozen()) out.add("Vault must not be frozen");
        if (vault.getBunkerCount() >= HKVault7000.HK7_MAX_BUNKERS) out.add("Bunker limit reached");
        return out;
    }

    static List<String> preconditionsForDeposit(HKVault7000 vault, String bunkerId, BigInteger amountWei) {
        List<String> out = new ArrayList<>();
        if (vault.isFrozen()) out.add("Vault must not be frozen");
        if (!vault.bunkerExists(bunkerId)) out.add("Bunker must exist");
        if (vault.isBunkerSettled(bunkerId)) out.add("Bunker must not be settled");
        if (amountWei == null || amountWei.signum() <= 0) out.add("Amount must be positive");
        if (vault.getVaultConfig().getMinDepositWei().signum() > 0 && amountWei.compareTo(vault.getVaultConfig().getMinDepositWei()) < 0) {
            out.add("Amount below minimum deposit");
        }
        return out;
    }

    static List<String> preconditionsForSettle(HKVault7000 vault, String bunkerId) {
        List<String> out = new ArrayList<>();
        if (vault.isFrozen()) out.add("Vault must not be frozen");
        if (!vault.bunkerExists(bunkerId)) out.add("Bunker must exist");
        if (vault.isBunkerSettled(bunkerId)) out.add("Bunker must not already be settled");
        return out;
    }

    static List<Integer> standardSequence() {
        return List.of(STEP_REGISTER, STEP_DEPOSIT, STEP_SETTLE, STEP_AUDIT);
    }

    static String runbookSummary() {
        return "HK7 Runbook: 1=Register 2=Deposit 3=Settle 4=Freeze 5=Thaw 6=Audit. Custodian required for 1,3,4,5.";
    }
}

// -----------------------------------------------------------------------------
// ENCODING UTILS (hex / bytes for EVM compatibility)
// -----------------------------------------------------------------------------

final class HK7EncodingUtils {
    private static final String HEX = "0123456789abcdef";

    static String toHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
