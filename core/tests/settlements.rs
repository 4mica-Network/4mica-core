use std::collections::BTreeMap;

use entities::sea_orm_active_enums::{ParticipantCycleRole, ParticipantCycleStatus};

#[path = "common/mod.rs"]
mod common;

use common::cycle_fixtures::{build_three_party_cycle, setup_cycle_service};
use core_service::persist::repo;

#[tokio::test]
#[serial_test::file_serial(db)]
async fn cycle_netting_offsets_bilateral_exposures_into_net_positions() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let cycle_id = "three-party-netting-cycle";
    let participants = build_three_party_cycle(&service, cycle_id).await?;
    let ctx = service.persist_ctx();

    service.compute_cycle_exposure_edges(cycle_id).await?;
    service
        .compute_cycle_participant_positions(cycle_id)
        .await?;

    let edges = repo::list_exposure_edges_for_cycle_on(ctx.db.as_ref(), cycle_id).await?;
    assert_eq!(edges.len(), 3);

    let positions =
        repo::list_participant_positions_for_cycle_on(ctx.db.as_ref(), cycle_id).await?;
    let by_participant = positions
        .into_iter()
        .map(|position| (position.participant.clone(), position))
        .collect::<BTreeMap<_, _>>();

    let alice = by_participant
        .get(&participants[0])
        .expect("alice position");
    assert_eq!(alice.net_debit, "9");
    assert_eq!(alice.role, ParticipantCycleRole::NetDebtor);
    assert_eq!(alice.status, ParticipantCycleStatus::Unpaid);

    let bob = by_participant.get(&participants[1]).expect("bob position");
    assert_eq!(bob.net_credit, "6");
    assert_eq!(bob.role, ParticipantCycleRole::NetCreditor);
    assert_eq!(bob.status, ParticipantCycleStatus::Claimable);

    let carol = by_participant
        .get(&participants[2])
        .expect("carol position");
    assert_eq!(carol.net_credit, "3");
    assert_eq!(carol.role, ParticipantCycleRole::NetCreditor);
    assert_eq!(carol.status, ParticipantCycleStatus::Claimable);

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn clearing_batch_balances_total_net_debit_and_credit() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let cycle_id = "clearing-batch-cycle";
    build_three_party_cycle(&service, cycle_id).await?;

    service.compute_cycle_exposure_edges(cycle_id).await?;
    service
        .compute_cycle_participant_positions(cycle_id)
        .await?;
    let batch = service.build_clearing_batch(cycle_id).await?;

    assert_eq!(batch.total_net_debit, "9");
    assert_eq!(batch.total_net_credit, "9");
    assert_eq!(batch.debtor_count, 1);
    assert_eq!(batch.creditor_count, 2);
    assert!(batch.merkle_root.starts_with("0x"));

    Ok(())
}
