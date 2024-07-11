#ifndef __VXLANMGR__
#define __VXLANMGR__

#include "dbconnector.h"
#include "producerstatetable.h"
#include "orch.h"

#include <map>
#include <vector>
#include <memory>
#include <string>
#include <utility>

namespace swss {

class VxlanMgr : public Orch
{
public:
    VxlanMgr(DBConnector *cfgDb, DBConnector *appDb, DBConnector *stateDb, const std::vector<std::string> &tableNames);
    using Orch::doTask;

    typedef struct VxlanInfo
    {
        std::string m_vxlanTunnel;
        std::string m_sourceIp;
        std::string m_vnet;
        std::string m_vni;
        std::string m_vxlan;
        std::string m_vxlanIf;
        std::string m_macAddress;
        std::string m_dstIp;
    } VxlanInfo;

    typedef struct TunCache
    {
        std::vector<FieldValueTuple> fvt;
        std::string m_sourceIp;
        uint32_t vlan_vni_refcnt;
    } TunCache;

    typedef struct TunRemoteCache
    {
        std::vector<FieldValueTuple> fvt;
        std::string m_sourceIp;
        uint32_t vni_refcnt;
        std::string m_localVtepIp;
    } TunRemoteCache;

    typedef struct MapCache
    {
        std::string vxlan_dev_name;
        std::string vlan;
        std::string vni_id;
    } MapCache;

    void waitTillReadyToReconcile();
    void beginReconcile(bool warm);
    void endReconcile(bool warm);
    void restoreVxlanNetDevices();
    bool isTunnelActive(std::string vxlanTunnelName);
    bool isRemoteTunnelActive(std::string vxlanRemoteTunnelName);

    ~VxlanMgr();
private:
    void doTask(Consumer &consumer);

    bool doVxlanCreateTask(const KeyOpFieldsValuesTuple & t);
    bool doVxlanDeleteTask(const KeyOpFieldsValuesTuple & t);

    bool doVxlanTunnelCreateTask(const KeyOpFieldsValuesTuple & t);
    bool doVxlanTunnelDeleteTask(const KeyOpFieldsValuesTuple & t);

    bool doVxlanTunnelMapCreateTask(const KeyOpFieldsValuesTuple & t);
    bool doVxlanTunnelMapDeleteTask(const KeyOpFieldsValuesTuple & t);

    bool doVxlanRemoteTunnelCreateTask(const KeyOpFieldsValuesTuple & t);
    bool doVxlanRemoteTunnelDeleteTask(const KeyOpFieldsValuesTuple & t);

    bool doVxlanRemoteTunnelMapCreateTask(const KeyOpFieldsValuesTuple & t);
    bool doVxlanRemoteTunnelMapDeleteTask(const KeyOpFieldsValuesTuple & t);

    bool doVxlanEvpnNvoCreateTask(const KeyOpFieldsValuesTuple & t);
    bool doVxlanEvpnNvoDeleteTask(const KeyOpFieldsValuesTuple & t);

    void createAppDBTunnelMapTable(const KeyOpFieldsValuesTuple & t);
    void delAppDBTunnelMapTable(std::string vxlanTunnelMapName);
    int createVxlanNetdevice(std::string vxlanTunnelName, std::string vni_id,
                             std::string src_ip, std::string dst_ip, std::string vlan_id);
    int createVxlanNetdeviceForRemoteVtep(std::string vxlanTunnelName, std::string vni_id,
                                          std::string src_ip, std::string dst_ip,
                                          std::string vlan_id);
    int downVxlanNetdevice(std::string vxlan_dev_name);
    int deleteVxlanNetdevice(std::string vxlan_dev_name);
    std::vector<std::string> parseNetDev(const std::string& stdout);
    void getAllVxlanNetDevices();

    /*
    * Query the state of vrf by STATE_VRF_TABLE
    * Return
    *  true: The state of vrf is OK
    *  false: the vrf hasn't been created
    */
    bool isVrfStateOk(const std::string & vrfName);
    bool isVxlanStateOk(const std::string & vxlanName);
    bool isVlanStateOk(const std::string &vlanName);
    std::pair<bool, std::string> getVxlanRouterMacAddress();

    bool createVxlan(const VxlanInfo & info);
    bool deleteVxlan(const VxlanInfo & info);

    void clearAllVxlanDevices();
    bool getFirstActiveTunnel(std::string &vxlanTunnelName);

    ProducerStateTable m_appVxlanTunnelTable,m_appVxlanTunnelMapTable,m_appEvpnNvoTable, m_appVxlanDataplaneVtepTable, m_appVxlanRemoteVniTable;
    Table m_cfgVxlanTunnelTable,m_cfgVnetTable,m_stateVrfTable,m_stateVxlanTable, m_appSwitchTable;
    Table m_stateVlanTable, m_stateNeighSuppressVlanTable, m_stateVxlanTunnelTable;

    /*
    * Vxlan Tunnel Cache
    * Key: tunnel name
    * Value: Field Value pairs of vxlan tunnel
    */
    std::map<std::string, TunCache > m_vxlanTunnelCache;
    std::map<std::string, MapCache> m_vxlanTunnelMapCache;
    std::map<std::string, std::string> m_vlanMapCache;
    std::map<std::string, std::string> m_vniMapCache;
    std::map<std::string, std::string> m_EvpnNvoCache;
    std::map<std::string, TunRemoteCache> m_vxlanRemoteVtepCache;
    std::map<std::string, std::string> m_vxlanRemoteTunnelMapCache;


    /*
    * Vnet Cache
    * Key: Vnet name
    * Value: Vxlan information of this vnet
    */
    std::map<std::string, VxlanInfo> m_vnetCache;

    DBConnector *m_app_db;
    bool m_in_reconcile;
    std::vector<std::string> m_appVxlanTunnelMapKeysRecon;
    std::map<std::string, std::string> m_vxlanNetDevices;
};

}

#endif
