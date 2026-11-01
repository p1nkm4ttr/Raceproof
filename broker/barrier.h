#ifndef RP_BARRIER_H
#define RP_BARRIER_H
/* Stage barrier between the broker child and the competing updater.
 *
 * If RP_BARRIER_DIR is set, the broker writes the stage name to
 * $RP_BARRIER_DIR/to_updater and blocks until it reads "go" from
 * $RP_BARRIER_DIR/from_updater. The updater attacks at the stage it was told to
 * and echoes "go" for every other stage. With RP_BARRIER_DIR unset every call is
 * a no-op, so the measured broker is the production broker apart from one check.
 *
 * Stages: pre_hash, post_hash, mid_copy, post_seal. */
void barrier_stage(const char *stage);
#endif
