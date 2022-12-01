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

import mount from '@tests/unit/setup'
import SidebarCtr from '../SidebarCtr.vue'

const mountFactory = opts =>
    mount({
        shallow: true,
        component: SidebarCtr,
        stubs: {
            'sql-editor': "<div class='stub'></div>",
        },
        ...opts,
    })

function mockShowingDbListTree() {
    return {
        getLoadingDbTree: () => false,
        getActiveQueryTabConn: () => ({ id: '1', name: 'server_0', type: 'servers' }),
    }
}

describe('sidebar-ctr', () => {
    let wrapper
    describe(`Child component's data communication tests`, () => {
        const evtFnMap = {
            'get-node-data': 'fetchNodePrvwData',
            'load-children': 'handleLoadChildren',
            'use-db': 'useDb',
            'alter-tbl': 'onAlterTable',
            'drop-action': 'handleOpenExecSqlDlg',
            'truncate-tbl': 'handleOpenExecSqlDlg',
        }
        Object.keys(evtFnMap).forEach(evt => {
            it(`Should call ${evtFnMap[evt]} if ${evt} is emitted from schema-tree-ctr`, () => {
                const spyFn = sinon.spy(SidebarCtr.methods, evtFnMap[evt])
                wrapper = mountFactory({
                    computed: { ...mockShowingDbListTree() },
                })
                const dbListTree = wrapper.findComponent({ name: 'schema-tree-ctr' })
                dbListTree.vm.$emit(evt)
                spyFn.should.have.been.called
                spyFn.restore()
            })
        })
    })

    describe(`computed properties tests`, () => {
        let wrapper
        it(`Should return accurate value for hasConn`, () => {
            // have no connection
            wrapper = mountFactory()
            expect(wrapper.vm.hasConn).to.be.false
            // Have valid connection
            wrapper = mountFactory({
                computed: { ...mockShowingDbListTree() },
            })
            expect(wrapper.vm.hasConn).to.be.true
        })
        it(`Should return accurate value for reloadDisabled`, async () => {
            // has connection
            wrapper = mountFactory({
                computed: {
                    hasConn: () => true,
                },
            })
            expect(wrapper.vm.reloadDisabled).to.be.false
            // have no connection and still loading for data
            await wrapper.setProps({ hasConn: false, isLoading: true })
            wrapper = mountFactory({
                computed: {
                    hasConn: () => false,
                    getLoadingDbTree: () => true,
                },
            })
            expect(wrapper.vm.reloadDisabled).to.be.true
        })
    })

    describe(`Methods tests`, () => {
        let wrapper
        it(`Should process fetchNodePrvwData method as expected`, () => {
            let clearDataPreviewCallCount = 0
            let queryModeParam, fetchPrvwParams
            const activeQueryTabId = 'QUERY_TAB_123_45'
            wrapper = mountFactory({
                methods: {
                    clearDataPreview: () => clearDataPreviewCallCount++,
                    SET_CURR_QUERY_MODE: mode => (queryModeParam = mode),
                    fetchPrvw: params => (fetchPrvwParams = params),
                },
                computed: { getActiveQueryTabId: () => activeQueryTabId },
            })
            const mockParam = { query_mode: 'PRVW_DATA', qualified_name: 'test.t1' }
            wrapper.vm.fetchNodePrvwData(mockParam)
            expect(clearDataPreviewCallCount).to.be.equals(1)
            expect(queryModeParam).to.be.eql({
                payload: mockParam.query_mode,
                id: activeQueryTabId,
            })
            expect(fetchPrvwParams).to.be.deep.equals({
                qualified_name: mockParam.qualified_name,
                query_mode: mockParam.query_mode,
            })
        })
        it(`Should call loadChildNodes when handleLoadChildren is called`, () => {
            let loadChildNodesParam
            wrapper = mountFactory({
                methods: {
                    loadChildNodes: param => (loadChildNodesParam = param),
                },
            })
            const mockNode = {
                key: 'node_key_20',
                type: 'Tables',
                name: 'Tables',
                id: 'test.Tables',
                qualified_name: 'test.Tables',
            }
            wrapper.vm.handleLoadChildren(mockNode)
            expect(loadChildNodesParam).to.be.deep.equals(mockNode)
        })
        it(`Should process onAlterTable method as expected`, async () => {
            let queryTblCreationInfoParam
            wrapper = mountFactory({
                computed: {
                    engines: () => [],
                    charset_collation_map: () => ({}),
                    def_db_charset_map: () => ({}),
                },
                methods: {
                    handleAddQueryTab: () => null,
                    queryAlterTblSuppData: () => null,
                    queryTblCreationInfo: param => (queryTblCreationInfoParam = param),
                },
            })
            const mockNode = {
                key: 'node_key_20',
                type: 'TABLE',
                name: 't1',
                id: 'test.Tables.t1',
                qualified_name: 'test.t1',
            }
            const fnsToBeSpied = [
                'handleAddQueryTab',
                'queryAlterTblSuppData',
                'queryTblCreationInfo',
            ]
            fnsToBeSpied.forEach(fn => {
                sinon.spy(wrapper.vm, fn)
            })

            await wrapper.vm.onAlterTable(mockNode) // trigger the method

            expect(queryTblCreationInfoParam).to.be.deep.equals(mockNode)
            fnsToBeSpied.forEach(fn => {
                wrapper.vm[fn].should.have.been.calledOnce
                wrapper.vm[fn].restore()
            })
        })
        it(`Should call exeStmtAction method when confirmExeStatements is called`, () => {
            const mockSql = 'truncate `test`.`t1`;'
            const mockActionName = 'truncate `test`.`t1`'
            wrapper = mountFactory({
                propsData: { execSqlDlg: { sql: mockSql } },
                data: () => ({ actionName: mockActionName }),
            })
            sinon.spy(wrapper.vm, 'exeStmtAction')
            wrapper.vm.confirmExeStatements() // trigger the method
            wrapper.vm.exeStmtAction.should.have.been.calledOnceWith({
                sql: mockSql,
                action: mockActionName,
            })
            wrapper.vm.exeStmtAction.restore()
        })
        it(`Should call PATCH_EXE_STMT_RESULT_MAP mutation when
          clearExeStatementsResult is called`, () => {
            const mockActive_wke_id = 'wke_abcd'
            wrapper = mountFactory({
                computed: { getActiveWkeId: () => mockActive_wke_id },
                methods: { PATCH_EXE_STMT_RESULT_MAP: () => null },
            })
            sinon.spy(wrapper.vm, 'PATCH_EXE_STMT_RESULT_MAP')
            wrapper.vm.clearExeStatementsResult() // trigger the method
            wrapper.vm.PATCH_EXE_STMT_RESULT_MAP.should.have.been.calledWith({
                id: mockActive_wke_id,
            })
            wrapper.vm.PATCH_EXE_STMT_RESULT_MAP.restore()
        })
    })

    describe(`Button tests`, () => {
        it(`Should disable reload-schemas button`, () => {
            wrapper = mountFactory({
                shallow: false,
                computed: { reloadDisabled: () => true },
            })
            expect(wrapper.find('.reload-schemas').attributes().disabled).to.be.equals('disabled')
        })
        it(`Should disable filter-objects input`, () => {
            wrapper = mountFactory({
                shallow: false,
                computed: { reloadDisabled: () => true },
            })
            expect(
                wrapper
                    .find('.filter-objects')
                    .find('input')
                    .attributes().disabled
            ).to.be.equals('disabled')
        })

        const btnHandlerMap = {
            'reload-schemas': 'fetchSchemas',
            'toggle-sidebar': 'SET_IS_SIDEBAR_COLLAPSED',
        }
        Object.keys(btnHandlerMap).forEach(btn => {
            it(`Should call ${btnHandlerMap[btn]} when ${btn} button is clicked`, async () => {
                let callCount = 0
                wrapper = mountFactory({
                    shallow: false,
                    computed: { reloadDisabled: () => false, is_sidebar_collapsed: () => false },
                    methods: {
                        [btnHandlerMap[btn]]: () => callCount++,
                    },
                })
                await wrapper.find(`.${btn}`).trigger('click')
                expect(callCount).to.be.equals(1)
            })
        })
    })
})
