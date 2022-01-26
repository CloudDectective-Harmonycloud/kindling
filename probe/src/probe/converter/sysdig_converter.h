//
// Created by 散养鸡 on 2021/12/13.
//

#ifndef HCMINE_SYSDIG_CONVERTER_H
#define HCMINE_SYSDIG_CONVERTER_H
#include "src/userspace/libsinsp/sinsp.h"
#include "src/probe/converter/converter.h"
using namespace kindling;

class sysdig_converter : public converter
{
public:
    void convert(kindling::KindlingEvent* kevt, void *evt);
    sysdig_converter(sinsp *);
    ~sysdig_converter();
    Category get_kindling_category(sinsp_evt *pEvt);
    Source get_kindling_source(uint16_t etype);
    L4Proto get_protocol(scap_l4_proto proto);
    ValueType get_type(ppm_param_type type);
    string get_kindling_name(sinsp_evt *pEvt);
private:
    // set source, name, timestamp, category according to list
	int init_kindling_event(kindling::KindlingEvent* kevt, sinsp_evt *sevt);
	int add_native_attributes(kindling::KindlingEvent* kevt, sinsp_evt *sevt);
	int add_user_attributes(kindling::KindlingEvent* kevt, sinsp_evt *sevt);
	int add_fdinfo(kindling::KindlingEvent* kevt, sinsp_evt *sevt);
	int add_threadinfo(kindling::KindlingEvent* kevt, sinsp_evt *sevt);

	sinsp *m_inspector;

    int setValue(AnyValue *pValue, ppm_param_type type, sinsp_evt_param *pParam);

    int setTuple(kindling::KindlingEvent* kevt, const sinsp_evt_param *pParam);
};

#endif //HCMINE_SYSDIG_CONVERTER_H
