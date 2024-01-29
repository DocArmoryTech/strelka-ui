import React, { useState } from "react";
import { Checkbox, Input, Row, Col, Modal } from "antd";
import "../../styles/OcrOverviewCard.css";

const OcrOverviewCard = ({ data }) => {
  const [isModalVisible, setIsModalVisible] = useState(false);
  const [wrapText, setWrapText] = useState(false);
  const [trimText, setTrimText] = useState(true);
  const [filter, setFilter] = useState("");

  const showModal = () => setIsModalVisible(true);
  const handleCancel = () => setIsModalVisible(false);

  let texts = Array.isArray(data.scan.ocr?.text)
    ? data.scan.ocr.text
    : [data.scan.ocr?.text || ""];
  const base64Thumbnail = data.scan.ocr?.base64_thumbnail;

  // Function to trim trailing whitespace or empty lines from a single line of text
  const trimLine = (line) => (trimText ? line.replace(/\s+$/, "") : line);

  // Function to trim all text content if it's not already an array
  texts = texts.map(trimLine);

  // Placeholder for Thumbnail in case its disabled / not functioning
  const ThumbnailPlaceholder = () => {
    return <div className="thumbnail-placeholder" />;
  };

  // Function to create line numbers and corresponding text
  const renderTextLines = (texts) => {
    let lineNumber = 1; // Initialize line number
    return texts.flatMap((textContent) => {
      // Split each text block by new lines and filter based on the user's input
      const lines = textContent
        .split(/\r?\n/)
        .filter((line) => !filter || line.includes(filter));
      // Map over each line and return a table row while incrementing the line number
      return lines.map((line) => (
        <tr key={lineNumber}>
          <td className="line-number">{lineNumber++}</td>
          <td className={`line-content ${wrapText ? "wrap" : "no-wrap"}`}>
            {line}
          </td>
        </tr>
      ));
    });
  };

  return (
    <div className="ocr-overview">
      <Row gutter={[16, 16]}>
        <Col span={18}>
          <Input
            placeholder="Filter"
            onChange={(e) => setFilter(e.target.value)}
            style={{ width: "100%" }}
          />
        </Col>
        <Col span={6}>
          <Checkbox
            checked={wrapText}
            onChange={(e) => setWrapText(e.target.checked)}
          >
            Wrap
          </Checkbox>
          <Checkbox
            checked={trimText}
            onChange={(e) => setTrimText(e.target.checked)}
          >
            Trim
          </Checkbox>
        </Col>
      </Row>
      <Row>
        <Col
          span={18}
          className="text-container"
          style={{ overflowX: wrapText ? "hidden" : "scroll" }}
        >
          <table>
            <tbody>{renderTextLines(texts)}</tbody>
          </table>
        </Col>
        <Col span={5} className="thumbnail-container">
        {base64Thumbnail ? (
            <>
              <img
                src={`data:image/jpeg;base64,${base64Thumbnail}`}
                alt="Email Preview"
                style={{
                  width: "auto",
                  maxHeight: "200px",
                  overflowY: "auto",
                  cursor: "pointer",
                }}
                onClick={showModal}
              />
              <Modal
                open={isModalVisible}
                footer={null}
                onCancel={handleCancel}
              >
                <img
                  src={`data:image/jpeg;base64,${base64Thumbnail}`}
                  alt="Email Preview (Expanded)"
                  style={{ width: "100%" }}
                />
              </Modal>
            </>
          ) : (
            <ThumbnailPlaceholder />
          )}
        </Col>
      </Row>
    </div>
  );
};

export default OcrOverviewCard;
