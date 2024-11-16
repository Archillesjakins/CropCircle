import React from "react";
import items from "../../components/Admin/db";
import Card from "../../components/Admin/Card";
import { CiFilter } from "react-icons/ci";
import { useState } from "react";
import "../../styles/Admin/verification.css"
const VerificationQueue = () => {

      const [showFilter, setShowFilter] = useState(false);
      const [filterStatus, setFilteredStatus] = useState("All");
      const [data, setData] = useState(items);

      const toggleFilter = () => {
        setShowFilter(true);
      };

      const handleFilter = (status) =>{
          setFilteredStatus(status);
          setShowFilter(false);
      }

      const filteredItems = filterStatus === "All" ? data : data.filter(item => item.status === filterStatus);

    


  return (
    <div>
      <div className="verificationHeader">
        <div className="verificationHeader__left">
          <h1>Products</h1>
          <p>({items.length} products)</p>
        </div>
        <div className="verificationHeader__right">
          <CiFilter className="filterIcon" onClick={toggleFilter} />
        </div>
      </div>

      <div className="verificationContainer">
        {filteredItems.map(({ name, price, status, numberOfItems, imageUrl, time, description }) => {
          return (
            <Card
              name={name}
              price={price}
              status={status}
              numberOfItems={numberOfItems}
              imageURL={imageUrl}
              time={time}
              description={description}
              onStatusChange = {(newStatus) => {
                setData(data.map(item => item.name === name ? {...item, status: newStatus} : item))
              }}
            />
          );
        })}
      </div>

      {showFilter ? (
        <div className="filterMenu">
          <button onClick={()=> handleFilter("All")}>All</button>
          <button onClick={()=> handleFilter("pending")}>Pending</button>
          <button onClick={()=> handleFilter("Approved")}>Approved</button>
          <button onClick={()=> handleFilter("Rejected")}>Rejected</button>
        </div>
      ) : null}


    </div>
  );
};

export default VerificationQueue;
