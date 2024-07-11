#include <unistd.h>
#include <algorithm>
#include <regex>
#include <sstream>
#include <string>
#include <net/if.h>

#include "logger.h"
#include "producerstatetable.h"
#include "macaddress.h"
#include "vxlanmgr.h"
#include "exec.h"
#include "tokenize.h"
#include "shellcmd.h"
#include "warm_restart.h"

using namespace std;
using namespace swss;

extern MacAddress gMacAddress;

// Fields name
#define VXLAN_TUNNEL "vxlan_tunnel"
#define SOURCE_IP "src_ip"
#define VNI "vni"
#define VNET "vnet"
#define VXLAN "vxlan"
#define VXLAN_IF "vxlan_if"

#define SWITCH "switch"
#define VXLAN_ROUTER_MAC "vxlan_router_mac"

#define VXLAN_NAME_PREFIX "Vxlan"
#define VXLAN_IF_NAME_PREFIX "Brvxlan"

#define VLAN "vlan"
#define DST_IP "dst_ip"
#define SOURCE_VTEP "source_vtep"
#define NVO_TYPE "type"
#define NVO_TYPE_DATA_PLANE "DATA_PLANE"

static std::string getVxlanName(const swss::VxlanMgr::VxlanInfo & info)
{
    return std::string("") + VXLAN_NAME_PREFIX + info.m_vni;
}

static std::string getVxlanIfName(const swss::VxlanMgr::VxlanInfo & info)
{
    return std::string("") + VXLAN_IF_NAME_PREFIX + info.m_vni;
}

// Commands

#define RET_SUCCESS 0

static int cmdCreateVxlan(const swss::VxlanMgr::VxlanInfo & info, std::string & res)
{
    // ip link add {{VXLAN}} type vxlan id {{VNI}} [local {{SOURCE IP}}] dstport 4789
    ostringstream cmd;
    cmd << IP_CMD " link add "
        << shellquote(info.m_vxlan)
        << " type vxlan id "
        << shellquote(info.m_vni)
        << " ";
    if (!info.m_sourceIp.empty())
    {
        cmd << " local " << shellquote(info.m_sourceIp);
    }
    cmd << " dstport 4789";
    return swss::exec(cmd.str(), res);
}

static int cmdUpVxlan(const swss::VxlanMgr::VxlanInfo & info, std::string & res)
{
    // ip link set dev {{VXLAN}} up
    ostringstream cmd;
    cmd << IP_CMD " link set dev "
        << shellquote(info.m_vxlan)
        << " up";
    return swss::exec(cmd.str(), res);
}

static int cmdCreateVxlanIf(const swss::VxlanMgr::VxlanInfo & info, std::string & res)
{
    // ip link add {{VXLAN_IF}} type bridge
    ostringstream cmd;
    cmd << IP_CMD " link add "
        << shellquote(info.m_vxlanIf)
        << " type bridge";
    return swss::exec(cmd.str(), res);
}

static int cmdAddVxlanIntoVxlanIf(const swss::VxlanMgr::VxlanInfo & info, std::string & res)
{
    // brctl addif {{VXLAN_IF}} {{VXLAN}}
    ostringstream cmd;
    cmd << BRCTL_CMD " addif "
        << shellquote(info.m_vxlanIf)
        << " "
        << shellquote(info.m_vxlan);
    if (!info.m_macAddress.empty())
    {
        // Change the MAC address of Vxlan bridge interface to ensure it's same with switch's.
        // Otherwise it will not response traceroute packets.
        // ip link set dev {{VXLAN_IF}} address {{MAC_ADDRESS}}
        cmd << " && " IP_CMD " link set dev "
            << shellquote(info.m_vxlanIf)
            << " address "
            << shellquote(info.m_macAddress);
    }
    return swss::exec(cmd.str(), res);
}

static int cmdAttachVxlanIfToVnet(const swss::VxlanMgr::VxlanInfo & info, std::string & res)
{
    // ip link set dev {{VXLAN_IF}} master {{VNET}}
    ostringstream cmd;
    cmd << IP_CMD " link set dev "
        << shellquote(info.m_vxlanIf)
        << " master "
        << shellquote(info.m_vnet);
    return swss::exec(cmd.str(), res);
}

static int cmdUpVxlanIf(const swss::VxlanMgr::VxlanInfo & info, std::string & res)
{
    // ip link set dev {{VXLAN_IF}} up
    ostringstream cmd;
    cmd << IP_CMD " link set dev "
        << shellquote(info.m_vxlanIf)
        << " up";
    return swss::exec(cmd.str(), res);
}

static int cmdDeleteVxlan(const swss::VxlanMgr::VxlanInfo & info, std::string & res)
{
    // ip link del dev {{VXLAN}}
    ostringstream cmd;
    cmd << IP_CMD " link del dev "
        << shellquote(info.m_vxlan);
    return swss::exec(cmd.str(), res);
}

static int cmdDeleteVxlanFromVxlanIf(const swss::VxlanMgr::VxlanInfo & info, std::string & res)
{
    // brctl delif {{VXLAN_IF}} {{VXLAN}}
    ostringstream cmd;
    cmd << BRCTL_CMD " delif "
        << shellquote(info.m_vxlanIf)
        << " " 
        << shellquote(info.m_vxlan);
    return swss::exec(cmd.str(), res);
}

static int cmdDeleteVxlanIf(const swss::VxlanMgr::VxlanInfo & info, std::string & res)
{
    // ip link del {{VXLAN_IF}}
    ostringstream cmd;
    cmd << IP_CMD " link del "
        << shellquote(info.m_vxlanIf);
    return swss::exec(cmd.str(), res);
}

static int cmdDetachVxlanIfFromVnet(const swss::VxlanMgr::VxlanInfo & info, std::string & res)
{
    // ip link set dev {{VXLAN_IF}} nomaster
    ostringstream cmd;
    cmd << IP_CMD " link set dev "
        << shellquote(info.m_vxlanIf)
        << " nomaster";
    return swss::exec(cmd.str(), res);
}

static int cmdEnableLearningOnVxlanIf(const swss::VxlanMgr::VxlanInfo & info, std::string & res)
{
    // bridge link set dev {{VXLAN_IF}} learning on
    ostringstream cmd;
    cmd << BRIDGE_CMD  " link set dev "
        << shellquote(info.m_vxlan)
        << " learning on ";
    return swss::exec(cmd.str(), res);
}

static int cmdEnableIngressReplicationOnVxlanIf(const swss::VxlanMgr::VxlanInfo & info, std::string & res)
{
    // bridge fdb append 00:00:00:00:00:00 dst {{DST_IP}} dev {{VXLAN_IF}} vni {{VNI}} static
    ostringstream cmd;
    cmd << BRIDGE_CMD  " fdb append 00:00:00:00:00:00 dst "
        << shellquote(info.m_dstIp)
        << " dev "
        << shellquote(info.m_vxlan)
        << " vni " << shellquote(info.m_vni)
        << " static ";
    return swss::exec(cmd.str(), res);
}

static int cmdDisableIngressReplicationOnVxlanIf(const swss::VxlanMgr::VxlanInfo & info, std::string & res)
{
    // bridge fdb del 00:00:00:00:00:00 dst {{DST_IP}} dev {{VXLAN_IF}} vni {{VNI}} static
    ostringstream cmd;
    cmd << BRIDGE_CMD  " fdb del 00:00:00:00:00:00 dst "
        << shellquote(info.m_dstIp)
        << " dev "
        << shellquote(info.m_vxlan)
        << " vni " << shellquote(info.m_vni)
        << " static ";
    return swss::exec(cmd.str(), res);
}

// Vxlanmgr

VxlanMgr::VxlanMgr(DBConnector *cfgDb, DBConnector *appDb, DBConnector *stateDb, const vector<std::string> &tables) :
        m_app_db(appDb),
        Orch(cfgDb, tables),
        m_appVxlanTunnelTable(appDb, APP_VXLAN_TUNNEL_TABLE_NAME),
        m_appVxlanTunnelMapTable(appDb, APP_VXLAN_TUNNEL_MAP_TABLE_NAME),
        m_appSwitchTable(appDb, APP_SWITCH_TABLE_NAME),
        m_appEvpnNvoTable(appDb, APP_VXLAN_EVPN_NVO_TABLE_NAME),
        m_cfgVxlanTunnelTable(cfgDb, CFG_VXLAN_TUNNEL_TABLE_NAME),
        m_cfgVnetTable(cfgDb, CFG_VNET_TABLE_NAME),
        m_stateVrfTable(stateDb, STATE_VRF_TABLE_NAME),
        m_stateVxlanTable(stateDb, STATE_VXLAN_TABLE_NAME),
        m_stateVlanTable(stateDb, STATE_VLAN_TABLE_NAME),
        m_stateNeighSuppressVlanTable(stateDb, STATE_NEIGH_SUPPRESS_VLAN_TABLE_NAME),
        m_stateVxlanTunnelTable(stateDb, STATE_VXLAN_TUNNEL_TABLE_NAME),
        m_appVxlanDataplaneVtepTable(appDb, APP_VXLAN_DATAPLANE_VTEP_TABLE_NAME),
        m_appVxlanRemoteVniTable(appDb, APP_VXLAN_DATAPLANE_REMOTE_VNI_TABLE_NAME)
{
    getAllVxlanNetDevices();

    if (!WarmStart::isWarmStart())
    {
        // Clear old vxlan devices that were created at last time.
        clearAllVxlanDevices();
    }

}

VxlanMgr::~VxlanMgr()
{
    clearAllVxlanDevices();
}

void VxlanMgr::doTask(Consumer &consumer)
{
    SWSS_LOG_ENTER();

    const string & table_name = consumer.getTableName();
    auto it = consumer.m_toSync.begin();
    while (it != consumer.m_toSync.end())
    {
        bool task_result = false;
        auto t = it->second;
        const std::string & op = kfvOp(t);

        if (op == SET_COMMAND)
        {
            if (table_name == CFG_VNET_TABLE_NAME)
            {
                task_result = doVxlanCreateTask(t);
            }
            else if (table_name == CFG_VXLAN_TUNNEL_TABLE_NAME)
            {
                task_result = doVxlanTunnelCreateTask(t);
            }
            else if (table_name == CFG_VXLAN_TUNNEL_MAP_TABLE_NAME)
            {
                task_result = doVxlanTunnelMapCreateTask(t);
            }
            else if (table_name == CFG_VXLAN_EVPN_NVO_TABLE_NAME)
            {
                task_result = doVxlanEvpnNvoCreateTask(t);
            }
            else if (table_name == CFG_VXLAN_REMOTE_TUNNEL_TABLE_NAME)
            {
                task_result = doVxlanRemoteTunnelCreateTask(t);
            }
            else if (table_name == CFG_VXLAN_REMOTE_TUNNEL_MAP_TABLE_NAME)
            {
                task_result = doVxlanRemoteTunnelMapCreateTask(t);
            }
            else
            {
                SWSS_LOG_ERROR("Unknown table : %s", table_name.c_str());
            }
        }
        else if (op == DEL_COMMAND)
        {
            if (table_name == CFG_VNET_TABLE_NAME)
            {
                task_result = doVxlanDeleteTask(t);
            }
            else if (table_name == CFG_VXLAN_TUNNEL_TABLE_NAME)
            {
                task_result = doVxlanTunnelDeleteTask(t);
            }
            else if (table_name == CFG_VXLAN_TUNNEL_MAP_TABLE_NAME)
            {
                task_result = doVxlanTunnelMapDeleteTask(t);
            }
            else if (table_name == CFG_VXLAN_EVPN_NVO_TABLE_NAME)
            {
                task_result = doVxlanEvpnNvoDeleteTask(t);
            }
            else if (table_name == CFG_VXLAN_REMOTE_TUNNEL_TABLE_NAME)
            {
                task_result = doVxlanRemoteTunnelDeleteTask(t);
            }
            else if (table_name == CFG_VXLAN_REMOTE_TUNNEL_MAP_TABLE_NAME)
            {
                task_result = doVxlanRemoteTunnelMapDeleteTask(t);
            }
            else
            {
                SWSS_LOG_ERROR("Unknown table : %s", table_name.c_str());
            }
        }
        else
        {
            SWSS_LOG_ERROR("Unknown command : %s", op.c_str());
        }

        if (task_result == true)
        {
            it = consumer.m_toSync.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

bool VxlanMgr::doVxlanCreateTask(const KeyOpFieldsValuesTuple & t)
{
    SWSS_LOG_ENTER();

    VxlanInfo info;
    info.m_vnet = kfvKey(t);
    for (auto i : kfvFieldsValues(t))
    {
        const std::string & field = fvField(i);
        const std::string & value = fvValue(i);
        if (field == VXLAN_TUNNEL)
        {
            info.m_vxlanTunnel = value;
        }
        else if (field == VNI)
        {
            info.m_vni = value;
        }
    }

    // If all information of vnet has been set
    if (info.m_vxlanTunnel.empty() 
     || info.m_vni.empty())
    {
        SWSS_LOG_DEBUG("Vnet %s information is incomplete", info.m_vnet.c_str());
        // if the information is incomplete, just ignore this message
        // because all information will be sent if the information was
        // completely set.
        return true;
    }

    // If the vxlan tunnel has been created
    auto it = m_vxlanTunnelCache.find(info.m_vxlanTunnel);
    if (it == m_vxlanTunnelCache.end())
    {
        SWSS_LOG_DEBUG("Vxlan tunnel %s has not been created", info.m_vxlanTunnel.c_str());
        // Suspend this message until the vxlan tunnel is created
        return false;
    }

    // If the VRF(Vnet is a special VRF) has been created
    if (!isVrfStateOk(info.m_vnet))
    {
        SWSS_LOG_DEBUG("Vrf %s has not been created", info.m_vnet.c_str());
        // Suspend this message until the vrf is created
        return false;
    }
    
    // If the mac address has been set
    auto macAddress = getVxlanRouterMacAddress();
    if (!macAddress.first)
    {
        SWSS_LOG_DEBUG("Mac address is not ready");
        // Suspend this message until the mac address is set
        return false;
    }
    info.m_macAddress = macAddress.second;

    auto sourceIp = std::find_if(
        it->second.fvt.begin(),
        it->second.fvt.end(),
        [](const FieldValueTuple & fvt){ return fvt.first == SOURCE_IP; });
    if (sourceIp  != it->second.fvt.end())
    {
        info.m_sourceIp = sourceIp->second;
    }
    info.m_vxlan = getVxlanName(info);
    info.m_vxlanIf = getVxlanIfName(info);

    // If this vxlan has been created
    if (isVxlanStateOk(info.m_vxlan))
    {
        // Because the vxlan has been create, so this message is to update 
        // the information of vxlan. 
        // This program just delete the old vxlan and create a new one
        // according to this message.
        doVxlanDeleteTask(t);
    }

    if (!createVxlan(info))
    {
        SWSS_LOG_ERROR("Cannot create vxlan %s", info.m_vxlan.c_str());
        return true;
    }

    m_vnetCache[info.m_vnet] = info;
    SWSS_LOG_INFO("Create vxlan %s", info.m_vxlan.c_str());

    return true;
}

bool VxlanMgr::doVxlanDeleteTask(const KeyOpFieldsValuesTuple & t)
{
    SWSS_LOG_ENTER();

    const std::string & vnetName = kfvKey(t);
    auto it = m_vnetCache.find(vnetName);
    if (it == m_vnetCache.end())
    {
        SWSS_LOG_WARN("Vxlan(Vnet %s) hasn't been created ", vnetName.c_str());
        return true;
    }

    const VxlanInfo & info = it->second;
    if (isVxlanStateOk(info.m_vxlan))
    {
        if ( ! deleteVxlan(info))
        {
            SWSS_LOG_ERROR("Cannot delete vxlan %s", info.m_vxlan.c_str());
            return false;
        }
    }
    else
    {
        SWSS_LOG_WARN("Vxlan %s hasn't been created ", info.m_vxlan.c_str());
    }

    SWSS_LOG_INFO("Delete vxlan %s", info.m_vxlan.c_str());
    m_vnetCache.erase(it);
    return true;
}

bool VxlanMgr::doVxlanTunnelCreateTask(const KeyOpFieldsValuesTuple & t)
{
    SWSS_LOG_ENTER();

    const std::string & vxlanTunnelName = kfvKey(t);
    
    // Update vxlan tunnel cache
    TunCache tuncache;

    tuncache.fvt = kfvFieldsValues(t);
    tuncache.vlan_vni_refcnt = 0;
    tuncache.m_sourceIp = "NULL";

    for (auto i : kfvFieldsValues(t))
    {
        const std::string & field = fvField(i);
        const std::string & value = fvValue(i);
        if (field == SOURCE_IP)
        {
            tuncache.m_sourceIp = value;
        }
    }

    m_appVxlanTunnelTable.set(vxlanTunnelName, kfvFieldsValues(t));
    m_vxlanTunnelCache[vxlanTunnelName] = tuncache;

    SWSS_LOG_NOTICE("Create vxlan tunnel %s", vxlanTunnelName.c_str());
    return true;
}


bool VxlanMgr::doVxlanRemoteTunnelCreateTask(const KeyOpFieldsValuesTuple & t)
{
    SWSS_LOG_ENTER();

    const std::string & vxlanRemoteTunnelName = kfvKey(t);
    
    // Update vxlan remote tunnel cache
    TunRemoteCache tuncache;

    // verify if there is a conflict with EVPN NVO
    if (! m_EvpnNvoCache.empty())
    {
        SWSS_LOG_WARN("Cannot configure dataplane remote VTEP when EVPN is inuse");
        return true;
    }

    if (isRemoteTunnelActive(vxlanRemoteTunnelName))
    {
        SWSS_LOG_WARN("VXLANRemoteTunnel: Remote VTEP %s already exists", vxlanRemoteTunnelName.c_str());
        return true;
    }

    tuncache.fvt = kfvFieldsValues(t);
    tuncache.vni_refcnt = 0;
    tuncache.m_sourceIp = "NULL";

    for (auto i : kfvFieldsValues(t))
    {
        const std::string & field = fvField(i);
        const std::string & value = fvValue(i);
        if (field == SOURCE_IP)
        {
            tuncache.m_sourceIp = value;
        }
    }

    // if first remote VTEP is configured, set source VTEP and enable learning on all data plane tunnels
    std::string sourceVtep;
    if (!getFirstActiveTunnel(sourceVtep))
    {
        SWSS_LOG_ERROR("Failed to get source VTEP");
        return true;
    }

    if (m_vxlanRemoteVtepCache.empty())
    {
        vector<FieldValueTuple> fvVector;
        FieldValueTuple s(SOURCE_VTEP, sourceVtep);
        fvVector.push_back(s);
        m_appVxlanDataplaneVtepTable.set(NVO_TYPE_DATA_PLANE, fvVector);

        // run over all created interfaces and enable learning for data plane tunnels
        std::map<std::string, MapCache>::iterator it;
        for (it = m_vxlanTunnelMapCache.begin(); it != m_vxlanTunnelMapCache.end(); it++)
        {
            size_t found = it->first.find(delimiter);
            const auto vxlanTunnelName = it->first.substr(0, found);
            if (vxlanTunnelName == sourceVtep)
            {
                swss::VxlanMgr::VxlanInfo info;
                std::string res;
                info.m_vxlan = it->second.vxlan_dev_name;
                info.m_vni = it->second.vni_id;
                SWSS_LOG_INFO("Enable learning on %s", info.m_vxlan.c_str());
                if (RET_SUCCESS != cmdEnableLearningOnVxlanIf(info, res))
                {
                    SWSS_LOG_ERROR("Failed to enable learning on vxlan interface %s. res %s", info.m_vxlan.c_str(), res.c_str());
                }
            }
        }
    }

    // create bridge port for remote VTEP

    m_vxlanRemoteVtepCache[vxlanRemoteTunnelName] = tuncache;
    m_vxlanRemoteVtepCache[vxlanRemoteTunnelName].m_localVtepIp = sourceVtep;

    SWSS_LOG_NOTICE("VXLANRemoteTunnel: Create vxlan remote tunnel %s", vxlanRemoteTunnelName.c_str());
    return true;
}

bool VxlanMgr::doVxlanTunnelDeleteTask(const KeyOpFieldsValuesTuple & t)
{
    SWSS_LOG_ENTER();

    const std::string & vxlanTunnelName = kfvKey(t);

    // If there is an NVO referring to this tunnel then hold on.
    std::map<std::string, std::string>::iterator it = m_EvpnNvoCache.begin();

    if ((it != m_EvpnNvoCache.end()) && (it->second == vxlanTunnelName))
    {
        SWSS_LOG_WARN("Tunnel %s deletion failed. Need to delete NVO", vxlanTunnelName.c_str());
        return false;
    }
      
    // If there are mappings still against this tunnel then hold on.
    if (m_vxlanTunnelCache[vxlanTunnelName].vlan_vni_refcnt)
    {
        SWSS_LOG_WARN("Tunnel %s deletion failed. Need to delete mapping entries", vxlanTunnelName.c_str());
        return false;
    }

    if (isTunnelActive(vxlanTunnelName))
    {
        m_appVxlanTunnelTable.del(vxlanTunnelName);
    }

    auto it1 = m_vxlanTunnelCache.find(vxlanTunnelName);
    if (it1 != m_vxlanTunnelCache.end())
    {
        m_vxlanTunnelCache.erase(it1);
    }

    SWSS_LOG_NOTICE("Delete vxlan tunnel %s", vxlanTunnelName.c_str());
    return true;
}

bool VxlanMgr::doVxlanRemoteTunnelDeleteTask(const KeyOpFieldsValuesTuple & t)
{
    SWSS_LOG_ENTER();

    const std::string & vxlanRemoteTunnelName = kfvKey(t);

    if (isRemoteTunnelActive(vxlanRemoteTunnelName))
    {
        m_vxlanRemoteVtepCache.erase(vxlanRemoteTunnelName);
    }

    if (m_vxlanRemoteVtepCache.empty())
    {
        SWSS_LOG_NOTICE("VXLANRemoteTunnel: Last Remote VTEP %s was removed - clear dataplane source VTEP", vxlanRemoteTunnelName.c_str());
        m_appVxlanDataplaneVtepTable.del(NVO_TYPE_DATA_PLANE);
    }

    SWSS_LOG_NOTICE("VXLANRemoteTunnel: Delete vxlan remote tunnel %s", vxlanRemoteTunnelName.c_str());
    return true;
}

bool VxlanMgr::doVxlanTunnelMapCreateTask(const KeyOpFieldsValuesTuple & t)
{
    int ret;
    SWSS_LOG_ENTER();

    std::string vxlanTunnelMapName = kfvKey(t);
    std::replace(vxlanTunnelMapName.begin(), vxlanTunnelMapName.end(), config_db_key_delimiter, delimiter);

    if (m_vxlanTunnelMapCache.find(vxlanTunnelMapName) != m_vxlanTunnelMapCache.end())
    {
        SWSS_LOG_ERROR("Map already present : %s", vxlanTunnelMapName.c_str());
        return true;
    }

    SWSS_LOG_INFO("Create vxlan tunnel map %s", vxlanTunnelMapName.c_str());
    std::string vlan, vlan_id, vni_id, src_ip, dst_ip("");
    for (auto i : kfvFieldsValues(t))
    {
        const std::string & field = fvField(i);
        const std::string & value = fvValue(i);
        if (field == VLAN)
        {
            vlan = value;
        }
        else if (field == VNI)
        {
            vni_id = value;
        }
    }

    // Check for VLAN or VNI if they are already mapped
    if (m_vlanMapCache.find(vlan) != m_vlanMapCache.end())
    {
        SWSS_LOG_ERROR("Vlan %s already mapped. Map Create failed for : %s", 
                      vlan.c_str(), vxlanTunnelMapName.c_str());
        return true;
    }

    if (m_vniMapCache.find(vni_id) != m_vniMapCache.end())
    {
        SWSS_LOG_ERROR("VNI %s already mapped. Map Create failed for : %s", 
                      vni_id.c_str(), vxlanTunnelMapName.c_str());
        return true;
    }

    const auto vlan_prefix = std::string("Vlan");
    const auto prefix_len = vlan_prefix.length();
    vlan_id = vlan.substr(prefix_len);

    size_t found = vxlanTunnelMapName.find(delimiter);
    const auto vxlanTunnelName = vxlanTunnelMapName.substr(0, found);

    // If the vxlan tunnel has been created
    auto it = m_vxlanTunnelCache.find(vxlanTunnelName);
    if (!isTunnelActive(vxlanTunnelName))
    {
        SWSS_LOG_INFO("Vxlan tunnel %s has not been created", vxlanTunnelName.c_str());
        // Suspend this message until the vxlan tunnel is created
        return false;
    }

    if (!isVlanStateOk(vlan))
    {
        SWSS_LOG_INFO("VLAN id is not yet created : %s",vxlanTunnelMapName.c_str());
        return false;
    }

    // Check the below condition only after the vxlanmgrd has reached reconcile state
    // The check to verify the state vxlan table is to take care of back to back 
    // create and delete of a VTEP object. On deletion of a VTEP object the FRR takes 
    // some time to remove all the routes and once all the routes are removed, the p2p 
    // tunnel is also removed. This check waits for all the p2p tunnels which were associated
    // with the earlier version of the VTEP to be deleted before processing further map entry 
    // creations.
    WarmStart::WarmStartState state;
    WarmStart::getWarmStartState("vxlanmgrd",state);
    if (state == WarmStart::RECONCILED)
    {
        if (m_vxlanTunnelMapCache.empty())
        {
            std::vector<std::string> keys;
            m_stateVxlanTunnelTable.getKeys(keys);
            if (!keys.empty())
            { 
                SWSS_LOG_WARN("State VXLAN tunnel table not yet empty.");
                return false;
            }
        }
    }

    auto sourceIp = std::find_if(
        it->second.fvt.begin(),
        it->second.fvt.end(),
        [](const FieldValueTuple & fvt){ return fvt.first == SOURCE_IP; });
    if (sourceIp  == it->second.fvt.end())
    {
        SWSS_LOG_DEBUG("Vxlan tunnel %s has no field src_ip", vxlanTunnelName.c_str());
        return true;
    }
    else
    {
        src_ip = sourceIp->second;
    }
    auto dstIp = std::find_if(
        it->second.fvt.begin(),
        it->second.fvt.end(),
        [](const FieldValueTuple & fvt){ return fvt.first == DST_IP; });
    if (dstIp  != it->second.fvt.end())
    {
        dst_ip = dstIp->second;
    }
    else
    {
        dst_ip = "";
    }

    createAppDBTunnelMapTable(t);
    SWSS_LOG_WARN("Create netdev for %s VNI(%s) VLAN(%s) - enter", 
                       vxlanTunnelName.c_str(), vni_id.c_str(), vlan_id.c_str());
    ret = createVxlanNetdevice(vxlanTunnelName, vni_id, src_ip, dst_ip, vlan_id);
    SWSS_LOG_WARN("Create netdev for %s VNI(%s) VLAN(%s) - enter", 
                       vxlanTunnelName.c_str(), vni_id.c_str(), vlan_id.c_str());
    if (ret != RET_SUCCESS)
    {
        SWSS_LOG_WARN("Vxlan Net Dev creation failure for %s VNI(%s) VLAN(%s)", 
                       vxlanTunnelName.c_str(), vni_id.c_str(), vlan_id.c_str());
    }

    std::string vxlan_dev_name;
    vxlan_dev_name = std::string("") + std::string(vxlanTunnelName) + "-" + std::string(vlan_id);

    MapCache map_entry;
    map_entry.vxlan_dev_name = vxlan_dev_name;
    map_entry.vlan = vlan;
    map_entry.vni_id = vni_id;

    m_vxlanTunnelMapCache[vxlanTunnelMapName] = map_entry;
    m_vlanMapCache[vlan] = vni_id;
    m_vniMapCache[vni_id] = vlan;
    m_vxlanTunnelCache[vxlanTunnelName].vlan_vni_refcnt++;

    //Inform the Vlan Mgr to update the tunnel flags if Arp/Nd Suppression is set.
    std::string key = "Vlan" + std::string(vlan_id);
    vector<FieldValueTuple> fvVector;
    FieldValueTuple s("netdev", vxlan_dev_name);
    fvVector.push_back(s);
    m_stateNeighSuppressVlanTable.set(key,fvVector);

    return true;
}


bool VxlanMgr::doVxlanRemoteTunnelMapCreateTask(const KeyOpFieldsValuesTuple & t)
{
    SWSS_LOG_ENTER();

    std::string vxlanRemoteTunnelMapName = kfvKey(t);
    std::replace(vxlanRemoteTunnelMapName.begin(), vxlanRemoteTunnelMapName.end(), config_db_key_delimiter, delimiter);

    SWSS_LOG_INFO("VXLANRemoteTunnel: Create vxlan remote tunnel map %s", vxlanRemoteTunnelMapName.c_str());

    if (m_vxlanRemoteTunnelMapCache.find(vxlanRemoteTunnelMapName) != m_vxlanRemoteTunnelMapCache.end())
    {
        SWSS_LOG_ERROR("VXLANRemoteTunnel: Map already present : %s", vxlanRemoteTunnelMapName.c_str());
        return true;
    }

    std::string vni_id;
    for (auto i : kfvFieldsValues(t))
    {
        const std::string & field = fvField(i);
        const std::string & value = fvValue(i);
        if (field == VNI)
        {
            vni_id = value;
        }
    }

    size_t found = vxlanRemoteTunnelMapName.find(delimiter);
    const auto vxlanRemoteTunnelName = vxlanRemoteTunnelMapName.substr(0, found);

    // If the vxlan tunnel has been created
    if (!isRemoteTunnelActive(vxlanRemoteTunnelName))
    {
        SWSS_LOG_INFO("VXLANRemoteTunnel: Vxlan remote tunnel %s has not been created", vxlanRemoteTunnelName.c_str());
        // Suspend this message until the vxlan tunnel is created
        return false;
    }

    if (m_vniMapCache.find(vni_id) == m_vniMapCache.end())
    {
        SWSS_LOG_ERROR("VXLANRemoteTunnel: VNI %s not yet mapped", vni_id.c_str());
        return false;
    }

    auto cache = m_vxlanRemoteVtepCache[vxlanRemoteTunnelName];

    // run over all created interfaces and enable ingress replication for data plane tunnels
    std::map<std::string, MapCache>::iterator it;
    for (it = m_vxlanTunnelMapCache.begin(); it != m_vxlanTunnelMapCache.end(); it++)
    {
        size_t found = it->first.find(delimiter);
        const auto vxlanTunnelName = it->first.substr(0, found);
        if (vxlanTunnelName == cache.m_localVtepIp)
        {
            swss::VxlanMgr::VxlanInfo info;
            std::string res;
            info.m_vxlan = it->second.vxlan_dev_name;
            info.m_dstIp = cache.m_localVtepIp;
            info.m_vni = vni_id;
            SWSS_LOG_INFO("Enable ingress replication on dev %s for ip %s vni %s", info.m_vxlan.c_str(), info.m_dstIp.c_str(), info.m_vni.c_str());
            if (RET_SUCCESS != cmdEnableIngressReplicationOnVxlanIf(info, res))
            {
                SWSS_LOG_ERROR("Failed to enable learning on vxlan interface %s. res %s", info.m_vxlan.c_str(), res.c_str());
            }
        }
    }


    string key = cache.m_sourceIp + ":" + vni_id;
    m_appVxlanRemoteVniTable.set(key, kfvFieldsValues(t));

    m_vxlanRemoteTunnelMapCache[vxlanRemoteTunnelMapName] = vni_id;
    cache.vni_refcnt++;

    SWSS_LOG_INFO("VXLANRemoteTunnel: Create vxlan remote vni %s - done", vxlanRemoteTunnelMapName.c_str());

    return true;
}

bool VxlanMgr::doVxlanTunnelMapDeleteTask(const KeyOpFieldsValuesTuple & t)
{
    SWSS_LOG_ENTER();

    std::string vxlanTunnelMapName = kfvKey(t);
    std::replace(vxlanTunnelMapName.begin(), vxlanTunnelMapName.end(), config_db_key_delimiter, delimiter);

    delAppDBTunnelMapTable(vxlanTunnelMapName);

    SWSS_LOG_INFO("Delete vxlan tunnel map %s", vxlanTunnelMapName.c_str());

    // ip link del dev {{VXLAN}}
    size_t found = vxlanTunnelMapName.find(delimiter);
    const auto vxlanTunnelName = vxlanTunnelMapName.substr(0, found);

    std::string vxlan_dev_name,vlan,vni_id;
    MapCache map_entry;

    try
    {
        map_entry = m_vxlanTunnelMapCache.at(vxlanTunnelMapName);
    }
    catch (const std::out_of_range& oor)
    {
        SWSS_LOG_ERROR("Error deleting tunmap : %s exception : %s", 
                      vxlanTunnelMapName.c_str(), oor.what());
        return true;
    }

    vxlan_dev_name = map_entry.vxlan_dev_name;
    vlan = map_entry.vlan;
    vni_id = map_entry.vni_id;

    // for each Remote Tunnel in Remote Tunnel Map - find Tunnel Map with same VNI
    std::string remoteVni;

    for (auto it = m_vxlanRemoteTunnelMapCache.begin();
         it != m_vxlanRemoteTunnelMapCache.end();
         it++)
    {
        remoteVni = it->second;
        if (vni_id == remoteVni)
        {
            std::string vxlanRemoteTunnelMapName = it->first;
            std::string vxlanRemoteTunnelName = vxlanRemoteTunnelMapName.substr(0, vxlanRemoteTunnelMapName.find(delimiter));
            SWSS_LOG_INFO("Found remote VTEP %s in VNI %s", vxlanRemoteTunnelName.c_str(), vni_id.c_str());
            if (isRemoteTunnelActive(vxlanRemoteTunnelName))
            {
                // Need to remove associated remote tunnel map prior to removing tunnel map
                SWSS_LOG_INFO("Vxlan tunnel map %s has associated remote tunnel map %s on vni %s", vxlanTunnelMapName.c_str(), vxlanRemoteTunnelName.c_str(), vni_id.c_str());
                return true;
            }
        }
    }

    downVxlanNetdevice(vxlan_dev_name);
    deleteVxlanNetdevice(vxlan_dev_name);

    m_vxlanTunnelMapCache.erase(vxlanTunnelMapName);
    m_vlanMapCache.erase(vlan);
    m_vniMapCache.erase(vni_id);
    m_vxlanTunnelCache[vxlanTunnelName].vlan_vni_refcnt--;

    //Delete the state table map of vlan to tunnel name.
    std::string vlan_delimiter = "-";
    found = vxlan_dev_name.find(vlan_delimiter);
    std::string key = "Vlan" + vxlan_dev_name.substr(found+1,vxlan_dev_name.length());
    SWSS_LOG_INFO("Delete Tunnel Map for %s -> %s ", key.c_str(), vxlan_dev_name.c_str());
    m_stateNeighSuppressVlanTable.del(key);
    return true;
}

bool VxlanMgr::doVxlanRemoteTunnelMapDeleteTask(const KeyOpFieldsValuesTuple & t)
{
    SWSS_LOG_ENTER();

    std::string vxlanRemoteTunnelMapName = kfvKey(t);
    std::replace(vxlanRemoteTunnelMapName.begin(), vxlanRemoteTunnelMapName.end(), config_db_key_delimiter, delimiter);

    SWSS_LOG_INFO("VXLANRemoteTunnel: Delete vxlan remote vnip %s", vxlanRemoteTunnelMapName.c_str());

    // ip link del dev {{VXLAN}}
    size_t found = vxlanRemoteTunnelMapName.find(delimiter);
    const auto vxlanRemoteTunnelName = vxlanRemoteTunnelMapName.substr(0, found);

    // If the vxlan tunnel has been created
    if (!isRemoteTunnelActive(vxlanRemoteTunnelName))
    {
        SWSS_LOG_INFO("VXLANRemoteTunnel: Vxlan remote tunnel %s has not been created", vxlanRemoteTunnelName.c_str());
        // Suspend this message until the vxlan tunnel is created
        return true;
    }

    std::string vni_id;
    MapCache map_entry;
    std::string ip_address, local_ip_address;

    try
    {
        vni_id = m_vxlanRemoteTunnelMapCache.at(vxlanRemoteTunnelMapName);
    }
    catch (const std::out_of_range& oor)
    {
        SWSS_LOG_ERROR("VXLANRemoteTunnel: Error getting tunmap : %s exception : %s", 
                      vxlanRemoteTunnelMapName.c_str(), oor.what());
        return true;
    }

    try
    {
        ip_address = m_vxlanRemoteVtepCache[vxlanRemoteTunnelName].m_sourceIp;
    }
    catch (const std::out_of_range& oor)
    {
        SWSS_LOG_ERROR("VXLANRemoteTunnel: Error getting  tunnel : %s exception : %s", 
                      vxlanRemoteTunnelName.c_str(), oor.what());
        return true;
    }

    try
    {
        local_ip_address = m_vxlanRemoteVtepCache[vxlanRemoteTunnelName].m_localVtepIp;
    }
    catch (const std::out_of_range& oor)
    {
        SWSS_LOG_ERROR("VXLANRemoteTunnel: Error getting  tunnel : %s exception : %s", 
                      vxlanRemoteTunnelName.c_str(), oor.what());
        return true;
    }

    if (m_vniMapCache.find(vni_id) == m_vniMapCache.end())
    {
        SWSS_LOG_ERROR("VXLANRemoteTunnel: VNI %s not yet mapped", vni_id.c_str());
        return true;
    }

    // run over all created interfaces and disable ingress replication for data plane tunnels
    std::map<std::string, MapCache>::iterator it;
    for (it = m_vxlanTunnelMapCache.begin(); it != m_vxlanTunnelMapCache.end(); it++)
    {
        size_t found = it->first.find(delimiter);
        const auto vxlanTunnelName = it->first.substr(0, found);
        if (vxlanTunnelName == local_ip_address)
        {
            swss::VxlanMgr::VxlanInfo info;
            std::string res;
            info.m_vxlan = it->second.vxlan_dev_name;
            info.m_dstIp = ip_address;
            info.m_vni = vni_id;
            SWSS_LOG_INFO("Enable ingress replication on dev %s for ip %s vni %s", info.m_vxlan.c_str(), info.m_dstIp.c_str(), info.m_vni.c_str());
            if (RET_SUCCESS != cmdDisableIngressReplicationOnVxlanIf(info, res))
            {
                SWSS_LOG_ERROR("Failed to disable learning on vxlan interface %s. res %s", info.m_vxlan.c_str(), res.c_str());
            }
        }
    }

    string key = ip_address + ":" + vni_id;
    m_appVxlanRemoteVniTable.del(key);

    m_vxlanRemoteTunnelMapCache.erase(vxlanRemoteTunnelMapName);
    m_vxlanRemoteVtepCache[vxlanRemoteTunnelName].vni_refcnt--;

   SWSS_LOG_INFO("VXLANRemoteTunnel: Delete vxlan remote tunnel map %s - done", vxlanRemoteTunnelMapName.c_str());
 
   return true;
}

bool VxlanMgr::doVxlanEvpnNvoCreateTask(const KeyOpFieldsValuesTuple & t)
{
    SWSS_LOG_ENTER();

    std::string EvpnNvoName = kfvKey(t);

    if (m_EvpnNvoCache.find(EvpnNvoName) != m_EvpnNvoCache.end())
    {
        SWSS_LOG_ERROR("Only Single NVO object allowed");
        return true;
    }

    // verify if there is a conflict with Dataplane tunnel
    if (! m_vxlanRemoteVtepCache.empty())
    {
        SWSS_LOG_WARN("Cannot configure EVPN when Dataplane is inuse");
        return false;
    }

    for (auto i : kfvFieldsValues(t))
    {
        const std::string & field = fvField(i);
        const std::string & value = fvValue(i);
        if (field == SOURCE_VTEP)
        {
            if (!isTunnelActive(value))
            {
                SWSS_LOG_ERROR("NVO %s creation failed. VTEP %s not present",EvpnNvoName.c_str(), value.c_str());
                return false;
            }
            m_EvpnNvoCache[EvpnNvoName] = value;
        }
    }

    std::replace(EvpnNvoName.begin(), EvpnNvoName.end(), config_db_key_delimiter, delimiter);
    m_appEvpnNvoTable.set(EvpnNvoName, kfvFieldsValues(t));

    SWSS_LOG_INFO("Create evpn nvo %s", EvpnNvoName.c_str());
    return true;
}

bool VxlanMgr::doVxlanEvpnNvoDeleteTask(const KeyOpFieldsValuesTuple & t)
{
    SWSS_LOG_ENTER();

    std::string EvpnNvoName = kfvKey(t);
    std::string vtep_name;
    try
    {
      vtep_name = m_EvpnNvoCache.at(EvpnNvoName);
    }
    catch (const std::out_of_range& oor)
    {
        SWSS_LOG_ERROR("NVOdeletion NVO : %s not found exception : %s", EvpnNvoName.c_str(), oor.what());
        return true;
    }

     // If there are mappings still then the NVO cannot be deleted.
    if (m_vxlanTunnelCache[vtep_name].vlan_vni_refcnt)
    {
        return false;
    }

    m_EvpnNvoCache.erase(EvpnNvoName);

    std::replace(EvpnNvoName.begin(), EvpnNvoName.end(), config_db_key_delimiter, delimiter);
    m_appEvpnNvoTable.del(EvpnNvoName);

    SWSS_LOG_INFO("Delete evpn nvo %s", EvpnNvoName.c_str());
    return true;
}

bool VxlanMgr::isVrfStateOk(const std::string & vrfName)
{
    SWSS_LOG_ENTER();

    std::vector<FieldValueTuple> temp;

    if (m_stateVrfTable.get(vrfName, temp))
    {
        SWSS_LOG_DEBUG("Vrf %s is ready", vrfName.c_str());
        return true;
    }
    SWSS_LOG_DEBUG("Vrf %s is not ready", vrfName.c_str());
    return false;
}

bool VxlanMgr::isVxlanStateOk(const std::string & vxlanName)
{
    SWSS_LOG_ENTER();
    std::vector<FieldValueTuple> temp;

    if (m_stateVxlanTable.get(vxlanName, temp))
    {
        SWSS_LOG_DEBUG("Vxlan %s is ready", vxlanName.c_str());
        return true;
    }
    SWSS_LOG_DEBUG("Vxlan %s is not ready", vxlanName.c_str());
    return false;
}

bool VxlanMgr::isVlanStateOk(const std::string &vlanName)
{
    SWSS_LOG_ENTER();
    std::vector<FieldValueTuple> temp;

    if (!vlanName.compare(0, strlen(VLAN_PREFIX), VLAN_PREFIX))
    {
        if (m_stateVlanTable.get(vlanName, temp))
        {
            SWSS_LOG_DEBUG("%s is ready", vlanName.c_str());
            return true;
        }
    }
    SWSS_LOG_INFO("%s is not ready", vlanName.c_str());
    return false;
}

std::pair<bool, std::string> VxlanMgr::getVxlanRouterMacAddress()
{
    std::vector<FieldValueTuple> temp;

    if (m_appSwitchTable.get(SWITCH, temp))
    {
        auto itr = std::find_if(
            temp.begin(),
            temp.end(),
            [](const FieldValueTuple &fvt) { return fvt.first == VXLAN_ROUTER_MAC; });
        if (itr != temp.end() && !(itr->second.empty()))
        {
            SWSS_LOG_DEBUG("Mac address %s is ready", itr->second.c_str());
            return std::make_pair(true, itr->second);
        }
        SWSS_LOG_DEBUG("Mac address will be automatically set");
        return std::make_pair(true, "");
    }
    
    SWSS_LOG_DEBUG("Mac address is not ready");
    return std::make_pair(false, "");
}

bool VxlanMgr::createVxlan(const VxlanInfo & info)
{
    SWSS_LOG_ENTER();
    
    std::string res;
    int ret = 0;

    // Create Vxlan
    ret = cmdCreateVxlan(info, res);
    if (ret != RET_SUCCESS)
    {
        SWSS_LOG_WARN(
            "Failed to create vxlan %s (vni: %s, source ip %s)",
            info.m_vxlan.c_str(),
            info.m_vni.c_str(),
            info.m_sourceIp.c_str());
        return false;
    }

    // Up Vxlan
    ret = cmdUpVxlan(info, res);
    if (ret != RET_SUCCESS)
    {
        cmdDeleteVxlan(info, res);
        SWSS_LOG_WARN(
            "Fail to up vxlan %s",
            info.m_vxlan.c_str());
        return false;
    }

    // Create Vxlan Interface
    ret = cmdCreateVxlanIf(info, res);
    if (ret != RET_SUCCESS)
    {
        cmdDeleteVxlan(info, res);
        SWSS_LOG_WARN(
            "Fail to create vxlan interface %s",
            info.m_vxlanIf.c_str());
        return false;
    }

    // Add vxlan into vxlan interface
    ret = cmdAddVxlanIntoVxlanIf(info, res);
    if ( ret != RET_SUCCESS )
    {
        cmdDeleteVxlanIf(info, res);
        cmdDeleteVxlan(info, res);
        SWSS_LOG_WARN(
            "Fail to add %s into %s",
            info.m_vxlan.c_str(),
            info.m_vxlanIf.c_str());
        return false;
    }

    // Attach vxlan interface to vnet
    ret = cmdAttachVxlanIfToVnet(info, res);
    if ( ret != RET_SUCCESS )
    {
        cmdDeleteVxlanFromVxlanIf(info, res);
        cmdDeleteVxlanIf(info, res);
        cmdDeleteVxlan(info, res);
        SWSS_LOG_WARN(
            "Fail to set %s master %s",
            info.m_vxlanIf.c_str(),
            info.m_vnet.c_str());
        return false;
       
    }

    // Up Vxlan Interface
    ret = cmdUpVxlanIf(info, res);
    if ( ret != RET_SUCCESS )
    {
        cmdDetachVxlanIfFromVnet(info, res);
        cmdDeleteVxlanFromVxlanIf(info, res);
        cmdDeleteVxlanIf(info, res);
        cmdDeleteVxlan(info, res);
        SWSS_LOG_WARN(
            "Fail to up bridge %s",
            info.m_vxlanIf.c_str());
        return false;
    }

    std::vector<FieldValueTuple> fvVector;
    fvVector.emplace_back("state", "ok");
    m_stateVxlanTable.set(info.m_vxlan, fvVector);

    return true;
}

bool VxlanMgr::deleteVxlan(const VxlanInfo & info)
{
    SWSS_LOG_ENTER();

    std::string res;

    cmdDetachVxlanIfFromVnet(info, res);
    cmdDeleteVxlanFromVxlanIf(info, res);
    cmdDeleteVxlanIf(info, res);
    cmdDeleteVxlan(info, res);

    m_stateVxlanTable.del(info.m_vxlan);

    return true;
}

void VxlanMgr::createAppDBTunnelMapTable(const KeyOpFieldsValuesTuple & t)
{
    std::string vxlanTunnelMapName = kfvKey(t);

    std::replace(vxlanTunnelMapName.begin(), vxlanTunnelMapName.end(), config_db_key_delimiter, delimiter);

    /* Case 1: Entry exist - Erase from cache & return
     * Case 2: Entry does not exist - Write to AppDB
     * Case 3: Entry exist but modified - Not taken care. Will address later
     */
    if (m_in_reconcile)
    {
        auto it = find(m_appVxlanTunnelMapKeysRecon.begin(), m_appVxlanTunnelMapKeysRecon.end(), vxlanTunnelMapName);
        if (it != m_appVxlanTunnelMapKeysRecon.end())
        {
            m_appVxlanTunnelMapKeysRecon.erase(it);
            SWSS_LOG_INFO("Reconcile App Tunnel Map Table create %s reconciled. Pending %zu",
                            vxlanTunnelMapName.c_str(), m_appVxlanTunnelMapKeysRecon.size());
            return;
        }
        else
        {
            SWSS_LOG_INFO("Reconcile App Tunnel Map Table create %s does not exist. Pending %zu",
                            vxlanTunnelMapName.c_str(), m_appVxlanTunnelMapKeysRecon.size());
        }
    }
    else
    {
        SWSS_LOG_INFO("App Tunnel Map Table create %s", vxlanTunnelMapName.c_str());
    }
    m_appVxlanTunnelMapTable.set(vxlanTunnelMapName, kfvFieldsValues(t));

    return;
}

void VxlanMgr::delAppDBTunnelMapTable(std::string vxlanTunnelMapName)
{
    m_appVxlanTunnelMapTable.del(vxlanTunnelMapName);
}

int VxlanMgr::createVxlanNetdevice(std::string vxlanTunnelName, std::string vni_id,
                                   std::string src_ip, std::string dst_ip,
                                   std::string vlan_id)
{
    std::string res, cmds;
    std::string link_add_cmd, link_set_master_cmd, link_up_cmd;
    std::string bridge_add_cmd, bridge_untagged_add_cmd, bridge_del_vid_cmd;
    std::string vxlan_dev_name;
    std::string learning_cmd;
    std::string bridge_learning_set_cmd;

    vxlan_dev_name = std::string("") + std::string(vxlanTunnelName) + "-" +
                     std::string(vlan_id);

    SWSS_LOG_INFO("Kernel tnl_name: %s vni_id: %s src_ip: %s dst_ip:%s vlan_id: %s",
                    vxlanTunnelName.c_str(), vni_id.c_str(), src_ip.c_str(), dst_ip.c_str(),
                    vlan_id.c_str());

    // Case 1: Entry exist - Erase from cache & return
    // Case 2: Entry does not exist - Create netDevice in Kernel
    // Case 3: Entry exist but modified - Not taken care. Will address later

    if (m_in_reconcile)
    {
        auto it = m_vxlanNetDevices.find(vxlan_dev_name);
        if (it != m_vxlanNetDevices.end())
        {
            m_vxlanNetDevices.erase(it);
            SWSS_LOG_INFO("Reconcile VxlanNetDevice %s reconciled. Pending %zu",
                            vxlan_dev_name.c_str(), m_vxlanNetDevices.size());
            return 0;
        }
        else
        {
            SWSS_LOG_INFO("Reconcile VxlanNetDevice %s does not exist. Pending %zu",
                            vxlan_dev_name.c_str(), m_vxlanNetDevices.size());
        }
    }
    else
    {
        SWSS_LOG_INFO("Creating VxlanNetDevice %s", vxlan_dev_name.c_str());
    }

    // ip link add <vxlan_dev_name> type vxlan id <vni> local <src_ip> remote <dst_ip> 
    // dstport 4789
    // ip link set <vxlan_dev_name> master DOT1Q_BRIDGE_NAME
    // bridge vlan add vid <vlan_id> dev <vxlan_dev_name>
    // bridge vlan add vid <vlan_id> untagged pvid dev <vxlan_dev_name>
    // ip link set <vxlan_dev_name> up

    if (!m_EvpnNvoCache.empty())
    {
        learning_cmd = "learning off ";
    }
    else
    {
        // enable learning for Data plane tunnels
        learning_cmd = "learning on ";
    }

    link_add_cmd = std::string("") + IP_CMD + " link add " + vxlan_dev_name + 
                   " address " + gMacAddress.to_string() + " type vxlan id " + 
                   std::string(vni_id) + " local " + src_ip + 
                   ((dst_ip  == "")? "":(" remote " + dst_ip)) + 
                   " nolearning " + " dstport 4789 ";
    
    link_set_master_cmd = std::string("") + IP_CMD + " link set " + 
                          vxlan_dev_name + " master Bridge ";

    link_up_cmd = std::string("") + IP_CMD + " link set " + vxlan_dev_name + " up ";

    bridge_add_cmd = std::string("") + BRIDGE_CMD + " vlan add vid " + 
                     std::string(vlan_id) + " dev " + vxlan_dev_name;

    bridge_untagged_add_cmd = std::string("") + BRIDGE_CMD + " vlan add vid " + 
                              std::string(vlan_id) + " untagged pvid dev " + vxlan_dev_name;

    bridge_del_vid_cmd = std::string("") + BRIDGE_CMD + " vlan del vid 1 dev " + 
                         vxlan_dev_name;

    bridge_learning_set_cmd = std::string("") + BRIDGE_CMD + " link set dev " + vxlan_dev_name + " " + learning_cmd;

    SWSS_LOG_INFO("Vxlan NetDevice link_add_cmd: %s", link_add_cmd.c_str());
    SWSS_LOG_INFO("Vxlan NetDevice link_set_master_cmd: %s", link_set_master_cmd.c_str());
    SWSS_LOG_INFO("Vxlan NetDevice link_up_cmd: %s", link_up_cmd.c_str());
    SWSS_LOG_INFO("Vxlan NetDevice bridge_add_cmd: %s", bridge_add_cmd.c_str());
    SWSS_LOG_INFO("Vxlan NetDevice bridge_untagged_add_cmd: %s", bridge_untagged_add_cmd.c_str());
    SWSS_LOG_INFO("Vxlan NetDevice bridge_del_vid_cmd: %s", bridge_del_vid_cmd.c_str());
    SWSS_LOG_INFO("Vxlan NetDevice bridge_learning_set_cmd: %s", bridge_learning_set_cmd.c_str());
    
    cmds = std::string("") + BASH_CMD + " -c \"" + 
           link_add_cmd + " && " + 
           link_set_master_cmd + " && " + 
           bridge_add_cmd + " && " + 
           bridge_untagged_add_cmd; 
        
    if ( vlan_id != "1")
    {
        cmds += bridge_del_vid_cmd + " && ";
    }

    cmds += bridge_learning_set_cmd + " && " +
            link_up_cmd + "\"";


    SWSS_LOG_INFO("Run bridge commands: <%s>", cmds.c_str());

    return swss::exec(cmds,res);
}

int VxlanMgr::createVxlanNetdeviceForRemoteVtep(std::string vxlanTunnelName, std::string vni_id,
                                             std::string src_ip, std::string dst_ip,
                                             std::string vlan_id)
{
    std::string res, cmds;
    std::string link_add_cmd, link_set_master_cmd, link_up_cmd;
    std::string bridge_add_cmd, bridge_untagged_add_cmd, bridge_del_vid_cmd;
    std::string vxlan_dev_name;
    std::string learning_cmd;
    std::string bridge_learning_set_cmd;

    vxlan_dev_name = std::string("") + std::string(vxlanTunnelName) + "-" +
                     std::string(vlan_id);

    SWSS_LOG_INFO("Kernel tnl_name: %s vni_id: %s src_ip: %s dst_ip:%s vlan_id: %s",
                    vxlanTunnelName.c_str(), vni_id.c_str(), src_ip.c_str(), dst_ip.c_str(),
                    vlan_id.c_str());

    // Case 1: Entry exist - Erase from cache & return
    // Case 2: Entry does not exist - Create netDevice in Kernel
    // Case 3: Entry exist but modified - Not taken care. Will address later

    if (m_in_reconcile)
    {
        auto it = m_vxlanNetDevices.find(vxlan_dev_name);
        if (it != m_vxlanNetDevices.end())
        {
            m_vxlanNetDevices.erase(it);
            SWSS_LOG_INFO("Reconcile VxlanNetDevice %s reconciled. Pending %zu",
                            vxlan_dev_name.c_str(), m_vxlanNetDevices.size());
            return 0;
        }
        else
        {
            SWSS_LOG_INFO("Reconcile VxlanNetDevice %s does not exist. Pending %zu",
                            vxlan_dev_name.c_str(), m_vxlanNetDevices.size());
        }
    }
    else
    {
        SWSS_LOG_INFO("Creating VxlanNetDevice %s", vxlan_dev_name.c_str());
    }

    // ip link add <vxlan_dev_name> type vxlan id <vni> local <src_ip> remote <dst_ip> 
    // dstport 4789
    // ip link set <vxlan_dev_name> master DOT1Q_BRIDGE_NAME
    // bridge vlan add vid <vlan_id> dev <vxlan_dev_name>
    // bridge vlan add vid <vlan_id> untagged pvid dev <vxlan_dev_name>
    // ip link set <vxlan_dev_name> up

    if (!m_EvpnNvoCache.empty())
    {
        learning_cmd = "learning off ";
    }
    else
    {
        // enable learning for Data plane tunnels
        learning_cmd = "learning on ";
    }

    link_add_cmd = std::string("") + IP_CMD + " link add " + vxlan_dev_name + 
                   " type vxlan id " + 
                   std::string(vni_id) + " local " + src_ip + 
                   ((dst_ip  == "")? "":(" remote " + dst_ip)) + 
                   " nolearning " + " dstport 4789 ";
    
    link_set_master_cmd = std::string("") + IP_CMD + " link set " + 
                          vxlan_dev_name + " master Bridge ";

    link_up_cmd = std::string("") + IP_CMD + " link set " + vxlan_dev_name + " up ";

    bridge_add_cmd = std::string("") + BRIDGE_CMD + " vlan add vid " + 
                     std::string(vlan_id) + " dev " + vxlan_dev_name;

    bridge_untagged_add_cmd = std::string("") + BRIDGE_CMD + " vlan add vid " + 
                              std::string(vlan_id) + " untagged pvid dev " + vxlan_dev_name;

    bridge_del_vid_cmd = std::string("") + BRIDGE_CMD + " vlan del vid 1 dev " + 
                         vxlan_dev_name;

    bridge_learning_set_cmd = std::string("") + BRIDGE_CMD + " link set dev " + vxlan_dev_name + " " + learning_cmd;

    SWSS_LOG_INFO("Vxlan NetDevice link_add_cmd: %s", link_add_cmd.c_str());
    SWSS_LOG_INFO("Vxlan NetDevice link_set_master_cmd: %s", link_set_master_cmd.c_str());
    SWSS_LOG_INFO("Vxlan NetDevice link_up_cmd: %s", link_up_cmd.c_str());
    SWSS_LOG_INFO("Vxlan NetDevice bridge_add_cmd: %s", bridge_add_cmd.c_str());
    SWSS_LOG_INFO("Vxlan NetDevice bridge_untagged_add_cmd: %s", bridge_untagged_add_cmd.c_str());
    SWSS_LOG_INFO("Vxlan NetDevice bridge_del_vid_cmd: %s", bridge_del_vid_cmd.c_str());
    SWSS_LOG_INFO("Vxlan NetDevice bridge_learning_set_cmd: %s", bridge_learning_set_cmd.c_str());
    
    cmds = std::string("") + BASH_CMD + " -c \"" + 
           link_add_cmd + " && " + 
           link_set_master_cmd + " && " + 
           bridge_add_cmd + " && " + 
           bridge_untagged_add_cmd; 
        
    if ( vlan_id != "1")
    {
        cmds += bridge_del_vid_cmd + " && ";
    }

    cmds += bridge_learning_set_cmd +  " && " +
            link_up_cmd + "\"";

    return swss::exec(cmds,res);
}

int VxlanMgr::downVxlanNetdevice(std::string vxlan_dev_name)
{
    int ret = 0;
    std::string res;
    const std::string cmd = std::string("") + IP_CMD + " link set dev " + vxlan_dev_name + " down";
    exec(cmd, res);
    return ret;
}

int VxlanMgr::deleteVxlanNetdevice(std::string vxlan_dev_name)
{    
    std::string res;
    const std::string cmd = std::string("") + IP_CMD  + " link del dev " + vxlan_dev_name;
    return swss::exec(cmd, res);
}

std::vector<std::string> VxlanMgr::parseNetDev(const string& stdout){
    std::vector<std::string> netdevs;
    std::regex device_name_pattern("^\\d+:\\s+([^:]+)");
    std::smatch match_result;
    auto lines = tokenize(stdout, '\n');
    for (const std::string & line : lines)
    {
        SWSS_LOG_DEBUG("line : %s\n",line.c_str());
        if (!std::regex_search(line, match_result, device_name_pattern))
        {
            continue;
        }
        std::string dev_name = match_result[1];
        netdevs.push_back(dev_name);
    }
    return netdevs;
}

void VxlanMgr::getAllVxlanNetDevices()
{
    std::string stdout;

    // Get VxLan Netdev Interfaces
    std::string cmd = std::string("") + IP_CMD + " link show type vxlan";
    int ret = swss::exec(cmd, stdout);
    if (ret != 0)
    {
        SWSS_LOG_ERROR("Cannot get vxlan devices by command : %s", cmd.c_str());
        stdout.clear();
    }
    std::vector<std::string> netdevs = parseNetDev(stdout);
    for (auto netdev : netdevs)
    {
        m_vxlanNetDevices[netdev] = VXLAN;
    }

    // Get VxLanIf Netdev Interfaces
    cmd = std::string("") + IP_CMD + " link show type bridge";
    ret = swss::exec(cmd, stdout);
    if (ret != 0)
    {
        SWSS_LOG_ERROR("Cannot get vxlanIf devices by command : %s", cmd.c_str());
        stdout.clear();
    }
    netdevs = parseNetDev(stdout);
    for (auto netdev : netdevs)
    {
        if (netdev.find(VXLAN_IF_NAME_PREFIX) == 0)
        {
            m_vxlanNetDevices[netdev] = VXLAN_IF;
        }
    }

    return;
}

void VxlanMgr::restoreVxlanNetDevices()
{
    /* Fetch the Src_ip from the vxlanAppTunnelTable */
    /* Currently, there is only 1 src vtep tunnel, hence picking the src_ip from that entry */
    Table vxlanAppTunnelTable = Table(this->m_app_db, APP_VXLAN_TUNNEL_TABLE_NAME);
    vector<std::string> appVxlanTunnelTableKeys;
    vxlanAppTunnelTable.getKeys(appVxlanTunnelTableKeys);
    std::string src_ip;
    std::string dst_ip("");
    dst_ip = "";
    for (auto &k : appVxlanTunnelTableKeys)
    {
        std::vector<FieldValueTuple> temp;
        if (vxlanAppTunnelTable.get(k, temp))
        {
            for (auto fv: temp)
            {
                std::string field = fvField(fv);
                std::string value = fvValue(fv);
                SWSS_LOG_INFO("RESTORE Vxlan Tunnel Table key: %s field: %s value: %s",
                        k.c_str(), field.c_str(), value.c_str());
                if (field == "src_ip")
                {
                    src_ip = value;
                    SWSS_LOG_INFO("RESTORE Vxlan Tunnel Table src_ip: %s", src_ip.c_str());
                }
            }
        }
        else
        {
            SWSS_LOG_INFO("RESTORE VxLAN Tunnel Table Key(%s)", k.c_str());
        }
    }

    Table vxlanAppTunnelMapTable = Table(this->m_app_db, APP_VXLAN_TUNNEL_MAP_TABLE_NAME);
    std::vector<std::string>::iterator it;
    for (it = m_appVxlanTunnelMapKeysRecon.begin();
         it != m_appVxlanTunnelMapKeysRecon.end();
         it++)
    {
        std::string vlan, vlan_id, vni_id;
        std::string vxlanTunnelMapName = *it;
        std::vector<FieldValueTuple> temp; 
        if (vxlanAppTunnelMapTable.get(vxlanTunnelMapName, temp))
        {
            for (auto fv: temp)
            {
                std::string field = fvField(fv);
                std::string value = fvValue(fv);
                SWSS_LOG_INFO("RESTORE Vxlan Tunnel MAP Table key: %s field: %s value: %s",
                        vxlanTunnelMapName.c_str(), field.c_str(), value.c_str());
                if (field == VLAN)
                {
                    vlan = value;
                }
                else if (field == VNI)
                {
                    vni_id = value;
                }
            }
        }
        else
        {
            SWSS_LOG_INFO("RESTORE VxLAN Tunnel Map Table Key(%s)", vxlanTunnelMapName.c_str());
        }
        const auto vlan_prefix = std::string("Vlan");
        const auto prefix_len = vlan_prefix.length();
        vlan_id = vlan.substr(prefix_len);

        size_t found = vxlanTunnelMapName.find(delimiter);
        const auto vxlanTunnelName = vxlanTunnelMapName.substr(0, found);

        int ret;
        ret = createVxlanNetdevice(vxlanTunnelName, vni_id, src_ip, dst_ip, vlan_id);
        if (ret != RET_SUCCESS)
        {
            SWSS_LOG_WARN("Vxlan Net Dev creation failure for %s VNI(%s) VLAN(%s)", 
                          vxlanTunnelName.c_str(), vni_id.c_str(), vlan_id.c_str());
        }

        SWSS_LOG_INFO("RESTORE Created Kernel Net Device (%s-%s)", vxlanTunnelName.c_str(), vlan_id.c_str());
    }

    SWSS_LOG_INFO("RESTORE Delete Stale Kernel Net Devices");
    clearAllVxlanDevices();
    SWSS_LOG_INFO("RESTORE Recreate Kernel Cache");
    getAllVxlanNetDevices();
}

void VxlanMgr::clearAllVxlanDevices()
{
    for (auto it = m_vxlanNetDevices.begin(); it != m_vxlanNetDevices.end();)
    {
        std::string netdev_name = it->first;
        std::string netdev_type = it->second;
        SWSS_LOG_INFO("Deleting Stale NetDevice %s, type: %s\n", netdev_name.c_str(), netdev_type.c_str());
        VxlanInfo info;
        std::string res;
        if (netdev_type.compare(VXLAN))
        {
            info.m_vxlan = netdev_name;
            downVxlanNetdevice(netdev_name);
            cmdDeleteVxlan(info, res);
        }
        else if(netdev_type.compare(VXLAN_IF))
        {
            info.m_vxlanIf = netdev_name;
            cmdDeleteVxlanIf(info, res);
        }
        it = m_vxlanNetDevices.erase(it);
    }
}

void VxlanMgr::waitTillReadyToReconcile()
{
    for (;;)
    {
        WarmStart::WarmStartState state;
        WarmStart::getWarmStartState("vlanmgrd", state);

        if ((WarmStart::REPLAYED == state) ||
            (WarmStart::RECONCILED == state))
        {
            SWSS_LOG_INFO("Vlanmgrd Reconciled %d", (int) state);
            return;
        }
        SWSS_LOG_INFO("Vlanmgrd NOT Reconciled %d", (int) state);            
        sleep(1);
    }
    return;
}

void VxlanMgr::beginReconcile(bool warm)
{
    m_in_reconcile = true;
    Table vxlanAppTunnelMapTable = Table(this->m_app_db, APP_VXLAN_TUNNEL_MAP_TABLE_NAME);
    vxlanAppTunnelMapTable.getKeys(m_appVxlanTunnelMapKeysRecon);
    for (auto &k : m_appVxlanTunnelMapKeysRecon)
    {
        SWSS_LOG_INFO("App Tunnel Map Key: %s", k.c_str());
    }
    SWSS_LOG_INFO("Pending %zu entries for the Tunnel Map Table", m_appVxlanTunnelMapKeysRecon.size());
    return;
}

void VxlanMgr::endReconcile(bool warm)
{
    /* Delete all stale entries from appDb */
    while (m_appVxlanTunnelMapKeysRecon.size())
    {
        std::vector<std::string>::iterator it = m_appVxlanTunnelMapKeysRecon.begin();
        if (it != m_appVxlanTunnelMapKeysRecon.end())
        {
            SWSS_LOG_INFO("Reconcile Deleting Stale Entry vxlandevname %s\n", m_appVxlanTunnelMapKeysRecon[0].c_str());
            delAppDBTunnelMapTable(m_appVxlanTunnelMapKeysRecon[0]);
            m_appVxlanTunnelMapKeysRecon.erase(it);
        }
    }
    SWSS_LOG_INFO("End App Tunnel Map Table Reconcile");

    /* Delete all the stale netDevices from the Kernel */
    clearAllVxlanDevices();

    m_in_reconcile = false;
}

bool VxlanMgr::isTunnelActive(std::string vxlanTunnelName)
{
    auto it = m_vxlanTunnelCache.find(vxlanTunnelName);
    if (it == m_vxlanTunnelCache.end())
    {
        return false;
    }

    if (m_vxlanTunnelCache[vxlanTunnelName].m_sourceIp == "NULL")
    {
        return false;
    }

    return true;
}

bool VxlanMgr::isRemoteTunnelActive(std::string vxlanRemoteTunnelName)
{
    auto it = m_vxlanRemoteVtepCache.find(vxlanRemoteTunnelName);
    if (it == m_vxlanRemoteVtepCache.end())
    {
        return false;
    }

    if (m_vxlanRemoteVtepCache[vxlanRemoteTunnelName].m_sourceIp == "NULL")
    {
        return false;
    }

    return true;
}

bool VxlanMgr::getFirstActiveTunnel(std::string &vxlanTunnelName)
{
    for (auto it = m_vxlanTunnelCache.begin(); it != m_vxlanTunnelCache.end(); it++)
    {
        if (m_vxlanTunnelCache[it->first].m_sourceIp == "NULL")
        {
            continue;
        }

        if (isTunnelActive(it->first))
        {
            vxlanTunnelName = it->first;
            return true;
        }
    }
    return false;
}
