import React, { useState, useEffect } from "react";
import { Avatar, Tag, Tooltip } from "antd";
import { CloudServerOutlined } from "@ant-design/icons";
import { fetchWithTimeout } from "../util";
import { APP_CONFIG } from "../config";

function SystemStatus() {
  const [isOnline, setIsOnline] = useState(false);

  useEffect(() => {
    fetchWithTimeout(`${APP_CONFIG.BACKEND_URL}/strelka/status/strelka`, {
      method: "GET",
      timeout: 5000,
    })
      .then((response) => {
        if (response.status === 200) {
          setIsOnline(true);
        } else {
          setIsOnline(false);
        }
      })
      .catch((error) => {
        setIsOnline(false);
      });
  }, []);

  return (
    <div>
      <Tooltip
        title={
          isOnline
            ? "Strelka server is available."
            : "Cannot connect to Strelka. File submission may not work. Contact your administrator for details."
        }
      >
      <Avatar
        style={{ backgroundColor: isOnline ? "#52c41a" : "#eb2f96" }}
        icon={<CloudServerOutlined />}
      />
      </Tooltip>
    </div>
  );
}

export default SystemStatus;
