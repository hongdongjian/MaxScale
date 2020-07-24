/*
 * Copyright (c) 2020 MariaDB Corporation Ab
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl11.
 *
 * Change Date: 2024-07-16
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */

import { expect } from 'chai'
import mount from '@tests/unit/setup'
import { mockupSelection, mockupInputChange } from '@tests/unit/mockup'
import FilterFormInput from '@CreateResource/Forms/FilterFormInput'

const mockupResourceModules = [
    {
        attributes: {
            module_type: 'Filter',
            parameters: [{ mandatory: true, name: 'filebase', type: 'string' }],
        },
        id: 'qlafilter',
    },

    {
        attributes: {
            module_type: 'Filter',
            parameters: [],
        },
        id: 'hintfilter',
    },
]

describe('FilterFormInput.vue', () => {
    let wrapper
    beforeEach(() => {
        localStorage.clear()

        wrapper = mount({
            shallow: false,
            component: FilterFormInput,
            props: {
                resourceModules: mockupResourceModules,
            },
        })
    })

    it(`Should pass the following props and have ref to module-parameters`, () => {
        const moduleParameters = wrapper.findComponent({ name: 'module-parameters' })
        const { moduleName, modules } = moduleParameters.vm.$props
        // props
        expect(moduleName).to.be.equals('module')
        expect(modules).to.be.deep.equals(wrapper.vm.$props.resourceModules)
        //ref
        expect(wrapper.vm.$refs.moduleInputs).to.be.not.null
    })
    it(`Should return an object with moduleId and parameters
      when getValues method get called`, async () => {
        // mockup select a filter module
        await mockupSelection(wrapper, mockupResourceModules[0])
        // get a filter parameter to mockup value changes
        const filterParameter = mockupResourceModules[0].attributes.parameters[0]
        const parameterCell = wrapper.find(`.${filterParameter.name}-cell-${1}`)
        const newValue = 'new value'
        await mockupInputChange(parameterCell, newValue)

        expect(wrapper.vm.getValues()).to.be.deep.equals({
            moduleId: mockupResourceModules[0].id,
            parameters: { [filterParameter.name]: newValue },
        })
    })
})
