import type {
  AbstractPowerSyncDatabase,
  PowerSyncBackendConnector,
} from '@powersync/web';
import {
  CrudEntry,
  UpdateType,
} from '@powersync/web';
import { supabase } from '../supabase';

export class SupabaseConnector implements PowerSyncBackendConnector {
  async fetchCredentials() {
    const {
      data: { session },
    } = await supabase.auth.getSession();

    if (!session) {
      throw new Error('Not authenticated');
    }

    return {
      endpoint: import.meta.env.VITE_POWERSYNC_URL || '',
      token: session.access_token,
    };
  }

  async uploadData(database: AbstractPowerSyncDatabase): Promise<void> {
    const transaction = await database.getNextCrudTransaction();
    if (!transaction) return;

    try {
      for (const op of transaction.crud) {
        await this.applyOp(op);
      }
      await transaction.complete();
    } catch (e) {
      console.error('Upload error:', e);
      throw e;
    }
  }

  private async applyOp(op: CrudEntry) {
    const table = op.table;
    const id = op.id;

    switch (op.op) {
      case UpdateType.PUT:
        await supabase.from(table).upsert({ id, ...op.opData });
        break;
      case UpdateType.PATCH:
        await supabase.from(table).update(op.opData!).eq('id', id);
        break;
      case UpdateType.DELETE:
        await supabase.from(table).delete().eq('id', id);
        break;
    }
  }
}
