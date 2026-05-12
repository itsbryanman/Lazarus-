//! Integration test for Phase 1.1: DedupTable round-trip.

use lazarus_core::snapshot::dedup::DedupTable;
use rusqlite::{Connection, params};

fn h(b: u8) -> [u8; 32] {
    [b; 32]
}

fn hex(b: u8) -> String {
    h(b).iter().map(|x| format!("{:02x}", x)).collect()
}

#[test]
fn dedup_round_trip_two_snapshots() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("catalog.db");

    {
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS Chunks (hash TEXT PRIMARY KEY, stored_size INTEGER NOT NULL, uncompressed_size INTEGER NOT NULL);",
        )
        .unwrap();
        for i in 1..=4u8 {
            conn.execute(
                "INSERT INTO Chunks (hash, stored_size, uncompressed_size) VALUES (?1, 0, 0)",
                params![hex(i)],
            )
            .unwrap();
        }
    }

    let mut dedup = DedupTable::open(&db).unwrap();

    dedup
        .add_references_batch("snap-a", &[h(1), h(2), h(3)])
        .unwrap();
    dedup
        .add_references_batch("snap-b", &[h(2), h(3), h(4)])
        .unwrap();

    assert_eq!(dedup.refcount(&h(1)).unwrap(), 1);
    assert_eq!(dedup.refcount(&h(2)).unwrap(), 2);
    assert_eq!(dedup.refcount(&h(3)).unwrap(), 2);
    assert_eq!(dedup.refcount(&h(4)).unwrap(), 1);

    let stats = dedup.stats().unwrap();
    assert_eq!(stats.referenced_chunks, 4);
    assert_eq!(stats.referencing_snapshots, 2);
    assert_eq!(stats.total_references, 6);
    assert!(dedup.unreferenced_chunks_hex().unwrap().is_empty());

    let dropped = dedup.drop_snapshot("snap-a").unwrap();
    assert_eq!(dropped, 3);
    assert_eq!(dedup.refcount(&h(1)).unwrap(), 0);
    assert_eq!(dedup.refcount(&h(2)).unwrap(), 1);
    assert_eq!(dedup.refcount(&h(3)).unwrap(), 1);
    assert_eq!(dedup.refcount(&h(4)).unwrap(), 1);

    let orphans = dedup.unreferenced_chunks_hex().unwrap();
    assert_eq!(orphans, vec![hex(1)]);

    dedup.drop_snapshot("snap-b").unwrap();
    let mut orphans = dedup.unreferenced_chunks_hex().unwrap();
    orphans.sort();
    assert_eq!(orphans, vec![hex(1), hex(2), hex(3), hex(4)]);
}
