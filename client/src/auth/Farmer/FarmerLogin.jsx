import React from "react";
import FarmerLoginBg from "../../assets/Background-images/young-asian-farmer-with-smartphone 1.png";

const FarmerLogin = () => {
  const formData = {
    email: "",
    password: "",
  };

  const dummyData = {
    email: "admin@admin.com",
    password: "123",
  };

  const [error, setError] = React.useState("");

  const [form, setForm] = React.useState(formData);
  function Handlechange(e) {
    setForm({ ...form, [e.target.name]: e.target.value });
    console.log(form);
  }

  function HandleSubmit(e) {
    e.preventDefault();
    if (form.email === "" && form.password === "") {
      alert("Please Enter the Credentials");
      return;
    }
    if (!form.email || !form.password) {
      setError("Please enter both email and password");
      return;
    }

    try{
      //const response = await fetch("http://...", form) 

      if(form.email === dummyData.email && form.password === dummyData.password){
        alert("Admin Login Successful");
        window.location.href = "/farmer/dashboard";
      }else{
        setError("Wrong Credentials");
      }
    }
    catch(error){
      setError("Something went wrong");
    }

    console.log(form);
  }
  return (
    <div
      className="flex h-screen bg-auto bg-no-repeat bg-right"
      style={{ backgroundImage: `url(${FarmerLoginBg})` }}
    >
      <div
        className="flex flex-col items-center w-full md:w-1/2 bg-white p-8 md:p-16 border border-green-400 "
        style={{
          borderBottomRightRadius: "3.4rem",
          borderTopRightRadius: "3.4rem",
        }}
      >
        <h1 className="text-green-600 text-3xl font-bold">FARMER SIGN IN</h1>
        <h2 className="text-xl font-semibold mt-4">Welcome Back</h2>
        <p className="text-gray-500 mt-2">Sign in to continue</p>
        <form onSubmit={HandleSubmit} action="" className="mt-8 space-y-4">
          <input
            type="email"
            placeholder="Email or Phone"
            name="email"
            value={form.email}
            onChange={Handlechange}
            className="w-full p-3 border border-gray-400 focus:outline-none focus:border-green-500 rounded"
          />
          <input
            type="password"
            placeholder="Password"
            name="password"
            value={form.password}
            onChange={Handlechange}
            className="w-full p-3 border border-gray-400 focus:outline-none focus:border-green-500 rounded"
          />
          <button
            type="submit"
            className="w-full bg-green-600 text-white p-3 rounded hover:bg-green-700"
          >
            Sign In
          </button>
        </form>
      </div>
    </div>
  );
};

export default FarmerLogin;
