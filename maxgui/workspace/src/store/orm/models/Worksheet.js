/*
 * Copyright (c) 2020 MariaDB Corporation Ab
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl11.
 *
 * Change Date: 2026-11-16
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */
import Extender from '@wsSrc/store/orm/Extender'
import { uuidv1 } from '@share/utils/helpers'
import { ORM_PERSISTENT_ENTITIES, ORM_TMP_ENTITIES } from '@wsSrc/store/config'

export default class Worksheet extends Extender {
    static entity = ORM_PERSISTENT_ENTITIES.WORKSHEETS

    /**
     * @returns {Object} - return fields that are not key, relational fields
     */
    static getNonKeyFields() {
        return { name: this.string('WORKSHEET') }
    }

    static fields() {
        return {
            id: this.uid(() => uuidv1()),
            ...this.getNonKeyFields(),
            active_query_tab_id: this.attr(null).nullable(),
            active_etl_task_id: this.attr(null).nullable(),
            // Below relationship fields are for QueryEditor when active_query_tab_id has value
            queryTabs: this.hasMany(ORM_PERSISTENT_ENTITIES.QUERY_TABS, 'worksheet_id'),
            schemaSidebar: this.hasOne(ORM_PERSISTENT_ENTITIES.SCHEMA_SIDEBARS, 'id'),
            queryEditorTmp: this.hasOne(ORM_TMP_ENTITIES.QUERY_EDITORS_TMP, 'id'),
        }
    }
}