# Changelog

All notable changes to the Elasticsearch Threat Hunting MCP Server will be documented in this file.

## [0.2.2] - 2025-12-20

### Added - Response Size Management
- **Automatic Response Size Limiting**: All tool responses now automatically limited to 8,000 tokens (~32KB) to prevent Claude Code context overflow
- **Intelligent Summarization**: Search results with >100 hits are automatically summarized
- **Chunk-by-Chunk Processing**: Large aggregations limited to top 50 buckets
- **Response Metadata**: All truncated responses include size information and truncation warnings
- **Per-Attack Pattern Limiting**: Threat hunting queries limit to 50 events per attack type

### Added - New Utility Module
- Created `src/utils/response_handler.py` with:
  - `limit_response_size()` - Main size limiting function
  - `summarize_search_response()` - Intelligent search result summarization
  - `summarize_hits()` - Hit-level summarization
  - `estimate_tokens()` - Token estimation
  - `truncate_text()` - Smart text truncation

### Changed - Enhanced Tools
- Updated `search_documents()` in DocumentClient with automatic size limiting
- Enhanced all ThreatHuntingClient methods:
  - `hunt_by_timeframe()` - Limits events per attack pattern
  - `analyze_failed_logins()` - Limits aggregation buckets
  - `search_with_lucene()` - Applies response size limits
  - All methods now return metadata about truncation

### Changed - Setup Script
- Updated to version 0.2.2
- Added "What's New" section highlighting response size limiting
- Added "Advanced Features" section in summary
- Enhanced user messaging about context overflow prevention

### Fixed
- **Critical**: Prevented "File content exceeds maximum allowed tokens" errors
- **Critical**: Fixed context window overflow when returning large search results
- Improved error handling for oversized responses

### Technical Details

**Size Limits:**
- Maximum response: 8,000 tokens (~32KB)
- Maximum hits per search: 100 (configurable)
- Maximum buckets per aggregation: 50
- Maximum events per attack pattern: 50

**Response Format:**
```json
{
  "response": { ... },
  "metadata": {
    "size_bytes": 25600,
    "estimated_tokens": 6400,
    "truncated": true,
    "original_size_bytes": 220000,
    "message": "Response automatically summarized due to size"
  }
}
```

## [0.2.1] - 2025-12-17

### Added - Threat Hunting Features
- 18 new threat hunting and incident response tools
- Asset Discovery system with metadata cataloguing
- EQL (Event Query Language) support
- Automated threat detection with 8 pre-built attack patterns
- IoC analysis with Pyramid of Pain prioritisation
- MITRE ATT&CK framework integration
- Read-only mode for safe production use

### Added - New Client Classes
- `AssetDiscoveryClient` - Asset discovery and metadata storage
- `EQLQueryClient` - EQL query execution
- `ThreatHuntingClient` - Automated threat hunting
- `IoCAnalysisClient` - Intelligent IoC extraction and analysis

### Added - Attack Pattern Detection
1. Brute Force (Event ID 4625, 4776)
2. Privilege Escalation (Event ID 4672, 4673, 4674)
3. Lateral Movement (Event ID 4624, 4648)
4. Persistence Mechanisms (Event ID 4697, 4698, 4720, 4732)
5. Suspicious Processes / LOLBins (Event ID 4688)
6. Encoded Commands / Obfuscated PowerShell
7. Credential Access / Dumping
8. Port Scanning / Network Reconnaissance

### Added - Documentation
- ARCHITECTURE.md - Complete technical reference
- THREAT_HUNTING_GUIDE.md - User-facing threat hunting guide
- AI_AGENT_INTEGRATION.md - AI agent behaviour guide
- CLAUDE_CODE_SETUP.md - Setup guide for Claude Code
- QUICK_START.md - 5-minute quick start
- HOW_TO_USE.md - Usage guide

### Changed
- Updated server.py to register new tool classes
- Extended SearchClient with multiple inheritance pattern
- Enhanced error handling and logging

## [2.0.0] - Original Release

### Added
- 18 original Elasticsearch tools
- Basic index operations
- Document CRUD operations
- Cluster health monitoring
- Alias management
- Data stream support
- Support for Elasticsearch 7.x, 8.x, 9.x
- Support for OpenSearch 1.x, 2.x, 3.x
- Multiple transport modes (stdio, SSE, HTTP)

---

## Migration Guide

### From 0.2.1 to 0.2.2

**No breaking changes** - This is a backward-compatible enhancement release.

**What's Different:**
- Tool responses may now include a `metadata` field with size information
- Large search results will be automatically truncated with clear messaging
- No configuration changes required

**Benefits:**
- No more "File content exceeds maximum tokens" errors
- Faster responses for large datasets
- Better Claude Code performance

**If you need the full dataset:**
- Use pagination with `from` and `size` parameters
- Use more specific queries to reduce result sets
- Check the `metadata.total_available` field to see how many results were truncated

---

For more information, see:
- [README.md](README.md) - Overview and installation
- [THREAT_HUNTING_GUIDE.md](THREAT_HUNTING_GUIDE.md) - Complete hunting guide
- [ARCHITECTURE.md](ARCHITECTURE.md) - Technical documentation
