package org.apache.ranger.trino;

import io.trino.jdbc.TrinoConnection;
import io.trino.jdbc.TrinoDriver;
import org.apache.ranger.AccessAuditsService;
import org.apache.ranger.common.SearchCriteria;
import org.apache.ranger.view.VXAccessAudit;
import org.apache.ranger.view.VXAccessAuditList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;

import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

@Service
@Scope("singleton")
public class TrinoAccessAuditService
    extends AccessAuditsService {

    private static final Logger log = LoggerFactory.getLogger(TrinoAccessAuditService.class);

    private static final String TRUE = "1=1";

    private static final String SEARCH_PARAM_USER = "requestUser";

    private static final String TRINO_REQUEST_USER = "requser";

    private static final String TRINO =
            "jdbc:trino://localhost:8080/%s/%s";

    private static final String auditeventsQuery = "SELECT * FROM trinologs.authzauditevent WHERE ";

    private Properties properties = new Properties();

    public TrinoAccessAuditService()
    {
        properties.setProperty("user", "system");
        properties.setProperty("SSL", "false");

    }

    public VXAccessAuditList searchXAccessAudits(SearchCriteria searchCriteria)
    {
        VXAccessAuditList accessAuditList = new VXAccessAuditList();
        String predicate = generatePredicate(searchCriteria);
        try {
            VXAccessAudit auditEvent = new VXAccessAudit();
            try (TrinoConnection connection = (TrinoConnection) new TrinoDriver()
                    .connect(String.format(TRINO, "hive", "trinologs"), this.properties)) {
                Statement statement = connection.createStatement();
                statement.closeOnCompletion();
                ResultSet resultSet = statement.executeQuery(auditeventsQuery + predicate);
                List<VXAccessAudit> audits = new ArrayList<>();
                if ( resultSet != null)
                {
                    while (resultSet.next()) {
                        auditEvent.setRepoType(resultSet.getInt("repositorytype"));
                        auditEvent.setRepoName(resultSet.getString("repo"));
                        auditEvent.setRequestUser(resultSet.getString("requser"));
                        //auditEvent.setEventTime(resultSet.getTimestamp("evttime"));
                        auditEvent.setAccessType(resultSet.getString("access"));
                        auditEvent.setResourcePath(resultSet.getString("resource"));
                        auditEvent.setResourceType(resultSet.getString("restype"));
                        auditEvent.setAction(resultSet.getString("action"));
                        auditEvent.setAccessResult(resultSet.getInt("result"));
                        auditEvent.setAgentHost(resultSet.getString("agent"));
                        auditEvent.setPolicyId(resultSet.getLong("policy"));
                        auditEvent.setResultReason(resultSet.getString("reason"));
                        auditEvent.setAclEnforcer(resultSet.getString("enforcer"));
                        auditEvent.setSessionId(resultSet.getString("sess"));
                        auditEvent.setClientType(resultSet.getString("clitype"));
                        auditEvent.setClientIP(resultSet.getString("cliip"));
                        auditEvent.setAgentHost(resultSet.getString("agenthost"));
                        auditEvent.setEventId(resultSet.getString("id"));
                        auditEvent.setSequenceNumber(resultSet.getLong("seq_num"));
                        auditEvent.setEventCount(resultSet.getLong("event_count"));
                        auditEvent.setEventDuration(resultSet.getLong("event_dur_ms"));
                        auditEvent.setTags(resultSet.getArray("tags").toString());
                        auditEvent.setClusterName(resultSet.getString("cluster_name"));
                        auditEvent.setZoneName(resultSet.getString("zone_name"));
                        auditEvent.setPolicyVersion(resultSet.getLong("policy_version"));
                        audits.add(auditEvent);
                    }
                }
                accessAuditList.setVXAccessAudits(audits);
            }
        }
        catch (Exception e) {
            log.error("Failed to Fetch Audit logs", e);
        }
        return accessAuditList;
    }

    private String generatePredicate(SearchCriteria searchCriteria)
    {
        if (searchCriteria == null)  {
            return TRUE;
        }

        if (searchCriteria.getParamList().containsKey(SEARCH_PARAM_USER)) {
            ArrayList<String> userlist = (ArrayList<String>)searchCriteria.getParamList().get(SEARCH_PARAM_USER);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < userlist.size(); i++) {
                sb.append("'" + userlist.get(i) + "'");
                if ( i != userlist.size() -1) sb.append(",");
            }

            if ( sb.length() > 0)
            {
                return String.format("%s in (%s)", TRINO_REQUEST_USER, sb);
            }
        }
        return TRUE;
    }

}
