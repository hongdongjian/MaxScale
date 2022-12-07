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
import Worksheet from '@queryEditorSrc/store/orm/models/Worksheet'
import WorksheetMem from '@queryEditorSrc/store/orm/models/WorksheetMem'
import QueryConn from '@queryEditorSrc/store/orm/models/QueryConn'
import Editor from '@queryEditorSrc/store/orm/models/Editor'
import SchemaSidebar from '@queryEditorSrc/store/orm/models/SchemaSidebar'

export default {
    namespaced: true,
    actions: {
        /**
         * This calls action to populate schema-tree and change the wke name to
         * the connection name.
         */
        async handleInitialFetch({ dispatch }) {
            try {
                const { id: connId, name: connName } = QueryConn.getters('getActiveQueryTabConn')
                const hasConnId = Boolean(connId)
                const isSchemaTreeEmpty = SchemaSidebar.getters('getDbTreeData').length === 0
                const hasSchemaTreeAlready =
                    this.vue.$typy(SchemaSidebar.getters('getCurrDbTree'), 'data_of_conn')
                        .safeString === connName
                if (hasConnId) {
                    if (isSchemaTreeEmpty || !hasSchemaTreeAlready) {
                        await SchemaSidebar.dispatch('initialFetch')
                        dispatch('changeWkeName', connName)
                    }
                    if (Editor.getters('getIsDDLEditor'))
                        await dispatch('editorsMem/queryAlterTblSuppData', {}, { root: true })
                }
            } catch (e) {
                this.vue.$logger.error(e)
            }
        },
        /**
         * If there is a connection bound to the worksheet being deleted, it
         * disconnects the connection bound to the worksheet and its cloned connections.
         * After that all entities related to the worksheet and itself will be purged.
         * @param {String} id - worksheet_id
         */
        async handleDeleteWke(_, id) {
            const { id: wkeConnId = '' } = QueryConn.getters('getWkeConnByWkeId')(id)
            // delete the wke connection and its clones (query tabs)
            if (wkeConnId) await QueryConn.dispatch('disconnect', { id: wkeConnId })
            Worksheet.cascadeDelete(id)
        },
        changeWkeName({ getters }, name) {
            Worksheet.update({ where: getters.getActiveWkeId, data: { name } })
        },
        /**
         * This action is used to execute statement or statements.
         * Since users are allowed to modify the auto-generated SQL statement,
         * they can add more SQL statements after or before the auto-generated statement
         * which may receive error. As a result, the action log still log it as a failed action.
         * @param {String} payload.sql - sql to be executed
         * @param {String} payload.action - action name. e.g. DROP TABLE table_name
         * @param {Boolean} payload.showSnackbar - show successfully snackbar message
         */
        async exeStmtAction({ rootState, dispatch, commit }, { sql, action, showSnackbar = true }) {
            const activeQueryTabConn = QueryConn.getters('getActiveQueryTabConn')
            const activeWkeId = Worksheet.getters('getActiveWkeId')
            const request_sent_time = new Date().valueOf()
            let stmt_err_msg_obj = {}
            const [e, res] = await this.vue.$helpers.asyncTryCatch(
                this.vue.$queryHttp.post(`/sql/${activeQueryTabConn.id}/queries`, {
                    sql,
                    max_rows: rootState.queryPersisted.query_row_limit,
                })
            )
            if (e) this.vue.$logger.error(e)
            else {
                const results = this.vue.$typy(res, 'data.data.attributes.results').safeArray
                const errMsgs = results.filter(res => this.vue.$typy(res, 'errno').isDefined)
                // if multi statement mode, it'll still return only an err msg obj
                if (errMsgs.length) stmt_err_msg_obj = errMsgs[0]

                WorksheetMem.update({
                    where: activeWkeId,
                    data: {
                        exe_stmt_result: {
                            data: this.vue.$typy(res, 'data.data.attributes').safeObject,
                            stmt_err_msg_obj,
                        },
                    },
                })

                let queryAction
                if (!this.vue.$typy(stmt_err_msg_obj).isEmptyObject)
                    queryAction = this.vue.$mxs_t('errors.failedToExeAction', { action })
                else {
                    queryAction = this.vue.$mxs_t('info.exeActionSuccessfully', { action })
                    if (showSnackbar)
                        commit(
                            'mxsApp/SET_SNACK_BAR_MESSAGE',
                            { text: [queryAction], type: 'success' },
                            { root: true }
                        )
                }
                dispatch(
                    'queryPersisted/pushQueryLog',
                    {
                        startTime: request_sent_time,
                        name: queryAction,
                        sql,
                        res,
                        connection_name: activeQueryTabConn.name,
                        queryType: rootState.queryEditorConfig.config.QUERY_LOG_TYPES.ACTION_LOGS,
                    },
                    { root: true }
                )
            }
        },
    },
    getters: {
        getAllWorksheets: () => Worksheet.all(),
        getActiveWke: (state, getters) => {
            return getters.getAllWorksheets.find(w => w.id === getters.getActiveWkeId) || {}
        },
        getActiveWkeId: (state, getters, rootState) => {
            const {
                ORM_NAMESPACE,
                ORM_PERSISTENT_ENTITIES: { WORKSHEETS },
            } = rootState.queryEditorConfig.config
            const { active_wke_id } = rootState[ORM_NAMESPACE][WORKSHEETS] || {}
            return active_wke_id
        },
        getActiveQueryTabId: () => Worksheet.getters('getActiveWke').active_query_tab_id,
        getExeStmtResult: () =>
            WorksheetMem.find(Worksheet.getters('getActiveWkeId')).exe_stmt_result || {},
    },
}