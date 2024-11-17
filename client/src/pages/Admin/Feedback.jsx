import React,{useState} from 'react'

const Feedback = () => {
 const feedbackData = [
   {id:1, name: "James Duntu", email: "jamesduntu@gmail.com", category: "Shipping Options", description: "Provide express ship...",  date: "Jan 17, 2022",status:"Reviewed",N:'Emmanuel Seyram',phone: "0555436783", address: "Blue-street, Accra", detailedDescription: "The tomato was rotten and that is not I ordered for. The tomato was rotten and that is not I ordered for"},
   {id:2, name: "James Duntu", email: "jamesduntu@gmail.com", category: "CheckOut Options", description: "Accept MobileMoney..", status:"Pending",phone: "0555436783",N:'Emmanuel Seyram', address: "Blue-street, Accra", detailedDescription: "The tomato which was rotten and that is not I ordered for. The tomato which was rotten and that is not I ordered for"},
   {id:3, name: "James Duntu", email: "jamesduntu@gmail.com", category: "Best Product", description: "Red Tomato is the best...",  date: "Jan 17, 2022",status:"Reviewed",N:'Emmanuel Seyram',phone: "0555436783", address: "Blue-street, Accra", detailedDescription: "The tomato which was rotten and that is not I ordered for. The tomato which was rotten and that is not I ordered for"},
   {id:4, name: "James Duntu", email: "jamesduntu@gmail.com", category: "Add feature", description: "Include green pepper big sizes",  date: "Jan 17, 2022",status:"Reviewed",N:'Emmanuel Seyram',phone: "0555436783", address: "Blue-street, Accra", detailedDescription: "The tomato which was rotten and that is not I ordered for. The tomato which was rotten and that is not I ordered for"},
   {id:5, name: "James Duntu", email: "jamesduntu@gmail.com", category: "Red Tomato", description: "Rotten Red Tomato",  date: "Jan 17, 2022",status:"Pending",N:'Emmanuel Seyram',phone: "0555436783", address: "Blue-street, Accra", detailedDescription: "The tomato which was rotten and that is not I ordered for. The tomato which was rotten and that is not I ordered for"},
  ]

  const statusStyles = {
    Reviewed: 'bg-green-100 text-green-700',
    Pending: 'bg-yellow-100 text-yellow-700',
  };

  const [selectedFeedback, setSelectedFeedback] = useState(null);

  const openModal = (feedback) => {
    setSelectedFeedback(feedback);
  };

  const closeModal = () => {
    setSelectedFeedback(null);
  };

  return (
    <div className='flex flex-col h-screen justify-center items-center bg-slate-50'>
    <div className="px-6 w-full sm:w-3/5 md:w-3/4 mx-auto shadow-2xl bg-white">

      <h2 className="text-lg sm:text-xl font-semibold text-gray-800">Feedback Review</h2>
      <p className="text-gray-500 mt-1">Lorem, ipsum dolor sit amet consectetur adipisic.</p>
      
      <div className="mt-6 space-y-2 sm:space-y-4">
        {feedbackData.map((item) => (                     
          <div
            key={item.id}
            className="flex md:flex-row flex-col items-start md:items-center justify-between p-4 border-t border-gray-200 cursor-pointer"
            onClick={() => openModal(item)}
          >
            <div className="flex flex-col w-1/4 pr-4">
              <p className="font-semibold text-gray-800">{item.name}</p>
              <p className="text-base text-gray-500">{item.email}</p>
            </div>
            
            <div className="flex flex-col w-1/4 pr-4">
              <p className="font-semibold text-gray-800">{item.category}</p>
              <p className="text-base text-gray-500 truncate">{item.description}</p>
            </div>
            
            <div className="flex flex-col w-1/4 pr-4"> 
              <p className="text-sm text-gray-500">{item.date}</p>
            </div>

            <div className="flex items-center w-1/4"> 
              <span className={`px-3 py-1 rounded-full text-sm font-semibold flex items-center ${statusStyles[item.status]}`}>
                <div className={`w-2 h-2 mr-2 rounded-full ${item.status === "Reviewed" ? "bg-green-700" : "bg-yellow-700"}`}></div>
                {item.status}
              </span>
            </div>
            
            <div className="text-gray-500 hover:text-gray-600 cursor-pointer">⋯</div>
          </div>
        ))}
      </div>

      {selectedFeedback && (
        <div className="fixed inset-0 bg-gray-800 bg-opacity-50 flex items-center justify-center">
          <div className="bg-white h-3/5 rounded-lg shadow-lg p-6 relative sm:w-2/5 w-full">
            <button className="absolute top-2 right-2 text-gray-400 hover:text-gray-800" onClick={closeModal}>✕</button>
            <h2 className="text-2xl font-bold mb-4">Feedback</h2>

            
            <div className="mb-4">
              <p className="text-lg font-semibold">{selectedFeedback.N}</p>
              <p className="text-gray-600">{selectedFeedback.email}</p>
              <p className="text-gray-600">{selectedFeedback.phone}</p>
              <p className="text-gray-600">{selectedFeedback.address}</p>
            </div>
           
            <div className='flex justify-between py-4'>
            <div className="mb-4">
              <h3 className="text-lg font-semibold">Description</h3>
              <div className="text-gray-600">
               {selectedFeedback.detailedDescription.split('. ').map((sentence, index) => (
                 <p key={index}>{sentence}.</p>
                      ))}
              </div>

            </div>

            <p className="text-gray-500">{selectedFeedback.date}</p>
            </div>

            <div className="absolute bottom-4 left-6 right-6 flex flex-col justify-end items-center">
              
              <span className={`px-4 mb-2 py-2 rounded-full text-white ${selectedFeedback.status === "Reviewed" ? "bg-green-500" : "bg-yellow-500"}`}>
              {selectedFeedback.status}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
    </div>
  );
}

export default Feedback;