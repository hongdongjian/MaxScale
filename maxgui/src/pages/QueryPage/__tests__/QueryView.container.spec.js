/*
 * Copyright (c) 2020 MariaDB Corporation Ab
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl11.
 *
 * Change Date: 2026-07-11
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */

import mount from '@tests/unit/setup'
import QueryView from '@/pages/QueryPage/QueryView.container.vue'
import { merge } from 'utils/helpers'

const mountFactory = opts =>
    mount(
        merge(
            {
                shallow: false,
                component: QueryView,

                computed: {
                    is_validating_conn: () => false,
                    worksheets_arr: () => [{ id: 'WORKSHEET_123' }],
                    active_wke_id: () => 'WORKSHEET_123',
                    ctrDim: () => ({ width: 1280, height: 800 }),
                },
                stubs: {
                    'sql-editor': "<div class='stub'></div>",
                    'readonly-sql-editor': "<div class='stub'></div>",
                },
            },
            opts
        )
    )

describe('query-view-ctr', () => {
    let wrapper

    it('Should pass accurate data to wke-ctr component via props', () => {
        wrapper = mountFactory()
        const wke = wrapper.findAllComponents({ name: 'wke-ctr' }).at(0)
        expect(wke.vm.$props.ctrDim).to.be.equals(wrapper.vm.ctrDim)
    })

    describe('Should assign corresponding handler for worksheet shortcut keys accurately', () => {
        let wrapper, txtEditorToolbar, wke, handleRunSpy, openSnippetDlgSpy, handleFileOpenSpy
        beforeEach(() => {
            wrapper = mountFactory()
            txtEditorToolbar = wrapper.vm.$typy(
                wrapper.vm.$refs,
                `wke[0].$refs.editor[0].$refs.txtEditorToolbar`
            ).safeObject
            wke = wrapper.findAllComponents({ name: 'wke-ctr' }).at(0)
            handleRunSpy = sinon.spy(txtEditorToolbar, 'handleRun')
            openSnippetDlgSpy = sinon.spy(txtEditorToolbar, 'openSnippetDlg')
            handleFileOpenSpy = sinon.spy(txtEditorToolbar.$refs.loadSqlCtr, 'handleFileOpen')
        })

        afterEach(() => {
            handleRunSpy.restore()
            openSnippetDlgSpy.restore()
            handleFileOpenSpy.restore()
        })

        it('Handle onCtrlEnter evt', () => {
            wke.vm.$emit('onCtrlEnter')
            handleRunSpy.should.have.been.calledOnce
            handleRunSpy.should.have.been.calledWith('selected')
        })
        it('Handle onCtrlShiftEnter evt', () => {
            wke.vm.$emit('onCtrlShiftEnter')
            handleRunSpy.should.have.been.calledOnce
            handleRunSpy.should.have.been.calledWith('all')
        })
        it('Handle onCtrlD evt', () => {
            wke.vm.$emit('onCtrlD')
            openSnippetDlgSpy.should.have.been.calledOnce
        })
        it('Handle onCtrlO evt', () => {
            wke.vm.$emit('onCtrlO')
            handleFileOpenSpy.should.have.been.calledOnce
        })
    })
})