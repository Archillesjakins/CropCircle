import React from "react";
import { useRef, useState } from "react";
import "../../styles/Admin/verification.css";
import { FaStar } from "react-icons/fa";
import { IoMdClose } from "react-icons/io";


const Card = ({
  name,
  price,
  status,
  numberOfItems,
  imageURL,
  time,
  description,
  onStatusChange,
}) => {

  const approve = () => {
    onStatusChange("Approved");

    closeDialog();
  };
  const reject = () => {
    onStatusChange("Rejected");

    closeDialog();
  };

  const [rating, setRating] = useState(null);
  const [hover, setHover] = useState(null);

  const dialogRef = useRef(null);

  const openDialog = () => {
    if (dialogRef.current) {
      dialogRef.current.showModal();
    } else {
      console.log("ref is null");
    }
  };

  const closeDialog = () => {
    if (dialogRef.current) {
      dialogRef.current.close();
    }
  };

  return (
    <div>
      <div className="verificationBody">
        <div className="verificationBody__title">
          <p
            className="status"
            style={{ color: status === "Rejected" ? "red" : "green" }}
          >
            {status}
          </p>
          <p>
            <img src={imageURL} alt="name" width={150} height={150} />
          </p>
          <div className="verificationBody__name">
            <div className="verificationBody__name--left">{name}</div>
            <div className="verificationBody__name--right">
              <button onClick={openDialog}>...</button>
            </div>
          </div>
          <p>{`Bag(${numberOfItems} pieces)`}</p>
          <p>GHC {price}</p>
          <div className="verificationBody__review">
            <p>
              {[...Array(5)].map((star, index) => {
                const currentRating = index + 1;
                return (
                  <label>
                    <input
                      type="radio"
                      name="rating"
                      id=""
                      value={currentRating}
                      onClick={() => setRating(currentRating)}
                    />
                    <FaStar
                      className="icon"
                      color={
                        currentRating <= (hover || rating)
                          ? "#ffc107"
                          : "e4e5e9"
                      }
                      onMouseEnter={() => setHover(currentRating)}
                      onMouseLeave={() => setHover(null)}
                    />
                  </label>
                );
              })}
              | {time}
            </p>
          </div>
        </div>
      </div>

      <dialog ref={dialogRef}>
        <div className="verificationBody__Dialog">
          <div className="verificationDialog__image">
            <img src={imageURL} alt="name" />
          </div>
          <div className="verificationDialog__description">
            <div className="verificationDialog__header">
              <h1>{name}</h1>
              <IoMdClose className="closeIcon" onClick={closeDialog} />
            </div>

            <p className="reviews">
              GHC {price} |
              {[...Array(5)].map((star, index) => {
                const currentRating = index + 1;
                return (
                  <label>
                    <input
                      type="radio"
                      name="rating"
                      id=""
                      value={currentRating}
                      onClick={() => setRating(currentRating)}
                    />
                    <FaStar
                      className="icon"
                      color={
                        currentRating <= (hover || rating)
                          ? "#ffc107"
                          : "#e4e5e9"
                      }
                      onMouseEnter={() => setHover(currentRating)}
                      onMouseLeave={() => setHover(null)}
                    />
                  </label>
                );
              })}
            </p>
            <h4>Description</h4>
            <p>{description}</p>
            <button className="approve" onClick={approve}>
              Approve
            </button>
            <button className="reject" onClick={reject}>
              Reject
            </button>
          </div>
        </div>
      </dialog>
    </div>
  );
};

export default Card;
