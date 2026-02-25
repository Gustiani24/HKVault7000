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
            sb.append(HEX.charAt((b >> 4) & 0x0f)).append(HEX.charAt(b & 0x0f));
        }
        return "0x" + sb.toString();
    }

    static byte[] fromHex(String hex) {
        if (hex == null) return new byte[0];
        String s = hex.trim().toLowerCase().startsWith("0x") ? hex.trim().substring(2) : hex.trim();
        if (s.length() % 2 != 0) s = "0" + s;
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    static String padAddressTo40(String address) {
        if (address == null) return HKVault7000.HK7_ZERO_ADDRESS;
        String s = address.trim().toLowerCase();
        if (s.startsWith("0x")) s = s.substring(2);
        if (s.length() >= 40) return "0x" + s.substring(s.length() - 40);
        return "0x" + "0".repeat(40 - s.length()) + s;
    }

    static boolean isZeroAddress(String address) {
        if (address == null) return true;
        String n = HK7AddressValidator.normalize(address);
        return n == null || n.equalsIgnoreCase(HKVault7000.HK7_ZERO_ADDRESS) || n.replace("0", "").replace("x", "").isEmpty();
    }
}

// -----------------------------------------------------------------------------
// VAULT REPORT (text / csv style output for off-chain tools)
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// GAS ESTIMATOR (off-chain only; approximate)
// -----------------------------------------------------------------------------

final class HK7GasEstimator {
    static final long BASE_REGISTER = 60_000L;
    static final long BASE_DEPOSIT = 50_000L;
    static final long BASE_SETTLE = 55_000L;
    static final long BASE_FREEZE = 30_000L;
    static final long BASE_THAW = 30_000L;
    static final long PER_STORAGE_SLOT = 20_000L;

    static long estimateRegisterBunker() {
        return BASE_REGISTER + PER_STORAGE_SLOT * 5;
    }

    static long estimateDeposit() {
        return BASE_DEPOSIT + PER_STORAGE_SLOT * 2;
    }

    static long estimateSettleBunker() {
        return BASE_SETTLE + PER_STORAGE_SLOT * 3;
    }

    static long estimateFreeze() { return BASE_FREEZE; }
    static long estimateThaw() { return BASE_THAW; }

    static Map<String, Long> estimateAll() {
        Map<String, Long> m = new HashMap<>();
        m.put("registerBunker", estimateRegisterBunker());
        m.put("deposit", estimateDeposit());
        m.put("settleBunker", estimateSettleBunker());
        m.put("freezeVault", estimateFreeze());
        m.put("thawVault", estimateThaw());
        return m;
    }
}

// -----------------------------------------------------------------------------
// VAULT REPORT (text / csv style output for off-chain tools)
// -----------------------------------------------------------------------------

final class HK7VaultReport {
    static String toCsvLine(String... cells) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < cells.length; i++) {
            if (i > 0) sb.append(",");
            String c = cells[i] != null ? cells[i] : "";
            if (c.contains(",") || c.contains("\"") || c.contains("\n")) {
                sb.append("\"").append(c.replace("\"", "\"\"")).append("\"");
            } else sb.append(c);
        }
        return sb.toString();
    }

    static List<String> buildBunkerCsv(HKVault7000 vault) {
        List<String> lines = new ArrayList<>();
        lines.add(toCsvLine("bunkerId", "tagHash", "balance", "createdAtBlock", "settled", "depositorCount"));
        for (String id : vault.getAllBunkerIds()) {
            HK7BunkerInfo info = vault.getBunkerInfo(id);
            int depCount = vault.getDepositorCount(id);
            lines.add(toCsvLine(id, info.getTagHash(), info.getBalance().toString(), String.valueOf(info.getCreatedAtBlock()),
                String.valueOf(info.isSettled()), String.valueOf(depCount)));
        }
        return lines;
    }

    static List<String> buildDepositsCsv(HKVault7000 vault, String bunkerId) {
        List<String> lines = new ArrayList<>();
        lines.add(toCsvLine("depositor", "amountWei"));
        Map<String, BigInteger> m = vault.getDepositLedger().getBunkerDepositsSnapshot(bunkerId);
        for (Map.Entry<String, BigInteger> e : m.entrySet()) {
            lines.add(toCsvLine(e.getKey(), e.getValue().toString()));
        }
        return lines;
    }

    static String buildSummaryText(HKVault7000 vault) {
        HK7VaultStats s = vault.getVaultStats();
        return String.format("HKVault7000 %s | bunkers=%d active=%d totalDeposited=%s totalSettled=%s vaultBalance=%s frozen=%s",
            HKVault7000.HK7_VERSION, s.getBunkerCount(), s.getActiveBunkerCount(), s.getTotalDepositedWei(), s.getTotalSettledWei(),
            s.getVaultTotalBalance(), s.isFrozen());
    }
}

// -----------------------------------------------------------------------------
// MAIN VAULT
// -----------------------------------------------------------------------------

/**
 * HKVault7000 — Bunker-style DeFi custody vault for EVM-aligned deployments.
 * <p>
 * Custodian registers bunkers; any address may deposit wei into an active bunker;
 * custodian settles bunkers, sending balance to the immutable treasury (with optional fee deduction).
 * All role addresses and limits are set at construction. Safe for mainnet use when deployed
 * with correct custodian and treasury and standard access controls enforced on-chain.
 * <p>
 * Events: BunkerRegistered, Deposited, BunkerSettled, TreasuryCredited, VaultFrozen, VaultThawed.
 * Errors: HK7_ZERO_BUNKER, HK7_ZERO_ADDR, HK7_NOT_CUSTODIAN, HK7_BUNKER_MISSING, HK7_BUNKER_EXISTS,
 * HK7_BUNKER_CLOSED, HK7_VAULT_FROZEN, HK7_XFER_FAIL, HK7_ZERO_AMT, HK7_BUNKER_CAP, HK7_BAD_INDEX.
 */
public final class HKVault7000 {

    // -------------------------------------------------------------------------
    // CONSTANTS (unique)
    // -------------------------------------------------------------------------

    /** Maximum number of bunkers that may be registered. */
    public static final int HK7_MAX_BUNKERS = 64;
    /** Maximum number of bunker ids returned in a single batch view call. */
    public static final int HK7_VIEW_BATCH_CAP = 24;
    /** Namespace / domain anchor for this vault (unique hex). */
    public static final String HK7_NAMESPACE_HEX = "0x9e1f4a7c0d3e6b9f2a5c8d1e4f7a0b3c6d9e2f5a8";
    /** Contract version string. */
    public static final String HK7_VERSION = "7000.1.0";

    // -------------------------------------------------------------------------
    // IMMUTABLE ADDRESSES (set at construction, never changed)
    // -------------------------------------------------------------------------

    private final String custodian;
    private final String treasury;
    private final long deployBlock;

    // -------------------------------------------------------------------------
    // STATE
    // -------------------------------------------------------------------------

    private final Set<String> bunkerIds = ConcurrentHashMap.newKeySet();
    private final Map<String, Boolean> bunkerSettled = new ConcurrentHashMap<>();
    private final Map<String, BigInteger> bunkerBalance = new ConcurrentHashMap<>();
    private final Map<String, String> bunkerTag = new ConcurrentHashMap<>();
    private final Map<String, Long> bunkerCreatedAtBlock = new ConcurrentHashMap<>();
    private final List<String> bunkerIdList = Collections.synchronizedList(new ArrayList<>());
    private final AtomicLong bunkerCount = new AtomicLong(0);
    private final AtomicLong totalDeposited = new AtomicLong(0);
    private final AtomicLong totalSettled = new AtomicLong(0);
    private final AtomicBoolean frozen = new AtomicBoolean(false);
    private final List<HK7EventListener> listeners = Collections.synchronizedList(new ArrayList<>());
    private final Object reentrancyLock = new Object();
    private final HK7FeeCalculator feeCalculator;
    private final HK7QuotaManager quotaManager;
    private final HK7DepositLedger depositLedger;
    private final HK7AuditLog auditLog;
    private final HK7VaultConfig vaultConfig;

    // -------------------------------------------------------------------------
    // CONSTRUCTOR (all addresses populated, no fill-in)
    // -------------------------------------------------------------------------

    public HKVault7000() {
        this.custodian = "0x4b7e9f2a5c8d1e4f7a0b3c6d9e2f5a8b1c4d7e0";
        this.treasury = "0x5c8f0a3b6d9e2f5a8b1c4d7e0f3a6b9c2d5e8f1";
        this.deployBlock = System.currentTimeMillis() / 1000L;
        if (!HK7AddressValidator.isValid(custodian) || !HK7AddressValidator.isValid(treasury)) {
            throw new HK7Exception("HK7_ZERO_ADDR", "Custodian or treasury address invalid");
        }
        this.feeCalculator = new HK7FeeCalculator(30);
        this.quotaManager = new HK7QuotaManager(
            BigInteger.valueOf(1000).multiply(BigInteger.TEN.pow(18)),
            BigInteger.valueOf(100).multiply(BigInteger.TEN.pow(18))
        );
        this.depositLedger = new HK7DepositLedger();
        this.auditLog = new HK7AuditLog();
        this.vaultConfig = new HK7VaultConfig(
            "0xfa2b",
            BigInteger.valueOf(1_000_000_000_000_000L),
            BigInteger.valueOf(500).multiply(BigInteger.TEN.pow(18)),
            30,
            "0x6d0e1f3a5c8b2d4e6f8a0b2c4d6e8f0a2b4c6d8e0"
        );
    }

    // -------------------------------------------------------------------------
    // ACCESSORS (immutable fields)
    // -------------------------------------------------------------------------

    public String getCustodian() { return custodian; }
    public String getTreasury() { return treasury; }
    public long getDeployBlock() { return deployBlock; }
    public boolean isFrozen() { return frozen.get(); }
    public long getBunkerCount() { return bunkerCount.get(); }
    public long getTotalDeposited() { return totalDeposited.get(); }
    public long getTotalSettled() { return totalSettled.get(); }

    // -------------------------------------------------------------------------
    // GUARDS
    // -------------------------------------------------------------------------

    private void requireCustodian(String sender) {
        if (sender == null || !HK7AddressValidator.normalize(sender).equalsIgnoreCase(HK7AddressValidator.normalize(custodian))) {
            throw new HK7Exception("HK7_NOT_CUSTODIAN", "Caller is not custodian");
        }
    }

    private void requireNotFrozen() {
        if (frozen.get()) throw new HK7Exception("HK7_VAULT_FROZEN", "Vault is frozen");
    }

    private void requireValidBunkerId(String bunkerId) {
        if (bunkerId == null || bunkerId.trim().isEmpty()) {
            throw new HK7Exception("HK7_ZERO_BUNKER", "Bunker id is zero or empty");
        }
    }

    private void requireBunkerExists(String bunkerId) {
        if (!bunkerIds.contains(bunkerId)) {
            throw new HK7Exception("HK7_BUNKER_MISSING", "Bunker not found");
        }
    }

    private void requireBunkerNotSettled(String bunkerId) {
        if (Boolean.TRUE.equals(bunkerSettled.get(bunkerId))) {
            throw new HK7Exception("HK7_BUNKER_CLOSED", "Bunker already settled");
        }
    }

    // -------------------------------------------------------------------------
    // CUSTODIAN: REGISTER BUNKER
    // -------------------------------------------------------------------------

    /**
     * Register a new bunker. Only custodian. Fails if vault frozen or bunker cap reached.
     */
    public void registerBunker(String bunkerId, String tagHash) {
        requireCustodian(Thread.currentThread().getName()); // in real EVM this would be msg.sender
        requireNotFrozen();
        requireValidBunkerId(bunkerId);
        if (bunkerIds.contains(bunkerId)) {
            throw new HK7Exception("HK7_BUNKER_EXISTS", "Bunker already exists");
        }
        if (bunkerCount.get() >= HK7_MAX_BUNKERS) {
            throw new HK7Exception("HK7_BUNKER_CAP", "Bunker limit reached");
        }
        bunkerIds.add(bunkerId);
        bunkerSettled.put(bunkerId, Boolean.FALSE);
        bunkerBalance.put(bunkerId, BigInteger.ZERO);
        bunkerTag.put(bunkerId, tagHash != null ? tagHash : "");
        long block = currentBlock();
        bunkerCreatedAtBlock.put(bunkerId, block);
        bunkerIdList.add(bunkerId);
        bunkerCount.incrementAndGet();
        HK7BunkerRegistered ev = new HK7BunkerRegistered(bunkerId, tagHash != null ? tagHash : "", block);
        dispatch(ev);
    }

    /**
     * Register bunker with caller passed explicitly (for simulation/testing).
     */
    public void registerBunkerFrom(String sender, String bunkerId, String tagHash) {
        String prev = Thread.currentThread().getName();
        try {
            Thread.currentThread().setName(sender != null ? sender : custodian);
            registerBunker(bunkerId, tagHash);
        } finally {
            Thread.currentThread().setName(prev);
        }
    }

    // -------------------------------------------------------------------------
    // PUBLIC: DEPOSIT
    // -------------------------------------------------------------------------

    /**
     * Deposit wei into an existing bunker. Reentrancy-safe, fails if frozen or bunker settled.
     * Enforces min/max per vault config and quota caps when applicable.
     */
    public void deposit(String bunkerId, String from, BigInteger amountWei) {
        requireNotFrozen();
        requireValidBunkerId(bunkerId);
        requireBunkerExists(bunkerId);
        requireBunkerNotSettled(bunkerId);
        if (HK7WeiMath.isZeroOrNegative(amountWei)) {
            throw new HK7Exception("HK7_ZERO_AMT", "Deposit amount must be positive");
        }
        if (vaultConfig.getMinDepositWei().signum() > 0 && amountWei.compareTo(vaultConfig.getMinDepositWei()) < 0) {
            throw new HK7Exception("HK7_ZERO_AMT", "Below minimum deposit");
        }
        if (vaultConfig.getMaxDepositPerTxWei().signum() > 0 && amountWei.compareTo(vaultConfig.getMaxDepositPerTxWei()) > 0) {
            throw new HK7Exception("HK7_ZERO_AMT", "Above max deposit per tx");
        }
        synchronized (reentrancyLock) {
            BigInteger prev = bunkerBalance.getOrDefault(bunkerId, BigInteger.ZERO);
            if (quotaManager.wouldExceedBunkerCap(bunkerId, prev, amountWei)) {
                throw new HK7Exception("HK7_BUNKER_CAP", "Bunker deposit cap exceeded");
            }
            BigInteger globalNow = BigInteger.valueOf(totalDeposited.get());
            if (quotaManager.wouldExceedGlobalCap(globalNow, amountWei)) {
                throw new HK7Exception("HK7_BUNKER_CAP", "Global deposit cap exceeded");
            }
            BigInteger next = HK7WeiMath.addSafe(prev, amountWei);
            bunkerBalance.put(bunkerId, next);
            totalDeposited.addAndGet(amountWei.longValue());
            depositLedger.recordDeposit(bunkerId, from, amountWei);
            auditLog.append("DEPOSIT", from != null ? from : "0x0", "bunker=" + bunkerId + " amount=" + amountWei);
        }
        long block = currentBlock();
        HK7Deposited ev = new HK7Deposited(bunkerId, from != null ? from : "0x0000000000000000000000000000000000000000", amountWei, block);
        dispatch(ev);
    }

    public void depositFrom(String sender, String bunkerId, BigInteger amountWei) {
        deposit(bunkerId, sender, amountWei);
    }

    // -------------------------------------------------------------------------
    // CUSTODIAN: SETTLE BUNKER (send balance to treasury)
    // -------------------------------------------------------------------------

    /**
     * Settle a bunker: mark as settled and credit its balance to treasury (simulated).
     * Fee is computed via fee calculator; net goes to treasury. In a real EVM contract this would perform actual transfers.
     */
    public void settleBunker(String bunkerId) {
        requireCustodian(Thread.currentThread().getName());
        requireNotFrozen();
        requireValidBunkerId(bunkerId);
        requireBunkerExists(bunkerId);
        requireBunkerNotSettled(bunkerId);
        synchronized (reentrancyLock) {
            BigInteger amount = bunkerBalance.getOrDefault(bunkerId, BigInteger.ZERO);
            bunkerSettled.put(bunkerId, Boolean.TRUE);
            if (amount.compareTo(BigInteger.ZERO) > 0) {
                BigInteger fee = feeCalculator.computeFee(amount);
                BigInteger netToTreasury = feeCalculator.amountAfterFee(amount);
                totalSettled.addAndGet(amount.longValue());
                long block = currentBlock();
                dispatch(new HK7TreasuryCredited(treasury, netToTreasury, block));
                auditLog.append("SETTLE", custodian, "bunker=" + bunkerId + " amount=" + amount + " fee=" + fee + " toTreasury=" + netToTreasury);
            }
            long block = currentBlock();
            dispatch(new HK7BunkerSettled(bunkerId, bunkerBalance.getOrDefault(bunkerId, BigInteger.ZERO), block));
        }
    }

    public void settleBunkerFrom(String sender, String bunkerId) {
        String prev = Thread.currentThread().getName();
        try {
            Thread.currentThread().setName(sender != null ? sender : custodian);
            settleBunker(bunkerId);
        } finally {
            Thread.currentThread().setName(prev);
        }
    }

    // -------------------------------------------------------------------------
    // CUSTODIAN: FREEZE / THAW
    // -------------------------------------------------------------------------

    public void freezeVault(String by) {
        requireCustodian(by != null ? by : Thread.currentThread().getName());
        frozen.set(true);
        long block = currentBlock();
        dispatch(new HK7VaultFrozen(by != null ? by : custodian, block));
    }

    public void thawVault(String by) {
