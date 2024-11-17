import React from "react";
import { useNavigate } from "react-router-dom";
import FarmerLoginBg from "../../assets/Background-images/young-asian-farmer-with-smartphone 1.png";


const FarmerLogin = () => {
  const navigate = useNavigate();
  const formData = {
    email: "",
    password: "",
  };
  const DummyData = {
    email: "admin@admin.com",
    password: "789",
  };

  const [form, setForm] = React.useState(formData);
  const [error, setError] = React.useState("");
  const [emailError, setEmailError] = React.useState("");
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;


  function Handlechange(e) {
    setForm({ ...form, [e.target.name]: e.target.value });
    if (!emailRegex.test(e.target.value)) {
      setEmailError("Please Enter a valid email address");
    }
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
    if (
      form.email === DummyData.email &&
      form.password === DummyData.password
    ) {
      window.location.href = "/farmer/overview";
    }
    else{
      alert("Wrong Credentials");
      setForm(formData);
    }
    // try {
    //   //const response = await fetch("http://...", form)

    //   if (
    //     form.email === dummyData.email &&
    //     form.password === dummyData.password
    //   ) {
    //     alert("Admin Login Successful");
    //     window.location.href = "/farmer/dashboard";
    //   } else {
    //     setError("Wrong Credentials");
    //   }
    // } catch (error) {
    //   setError("Something went wrong");
    // }

    console.log(form);
  }
  return (
    <div
      className="flex items-center justify-center h-screen bg-right bg-no-repeat bg-cover lg:justify-start lg:bg-auto"
      style={{ backgroundImage: `url(${FarmerLoginBg})` }}
    >

      <div className="flex flex-col items-center justify-center w-10/12 p-8 pb-12 bg-white border border-green-400 md:w-3/4 lg:w-1/2 lg:h-lvh lg:p-24 opacity-90 md:p-16 rounded-3xl lg:rounded-tl-none lg:rounded-bl-none ">
        <h1 className="text-3xl font-bold text-green-600">FARMER SIGN IN</h1>
        <h2 className="mt-4 text-xl font-semibold">Welcome Back</h2>
        <p className="mt-2 text-gray-500">Sign in to continue</p>

        <form onSubmit={HandleSubmit} action="" className="mt-8 space-y-4">
          <input
            type="email"
            placeholder="Email or Phone"
            name="email"
            value={form.email}
            onChange={Handlechange}
            className="w-full p-3 border border-gray-400 rounded focus:outline-none focus:border-green-500"
          />
          <input
            type="password"
            placeholder="Password"
            name="password"
            value={form.password}
            onChange={Handlechange}
            className="w-full p-3 border border-gray-400 rounded focus:outline-none focus:border-green-500"
          />
          <button
            type="submit"
            className="w-full p-3 text-white bg-green-600 rounded-xl hover:bg-green-700"
          >
            Sign In
          </button>
        </form>
        <p className="mt-4 text-sm text-center text-gray-500">
          Don't have an account?{" "}
          <button
            onClick={() => navigate("/farmer/signup")}
            className="text-green-600 cursor-pointer"
          >
            Log In
          </button>
        </p>
      </div>
    </div>
  );
};

export default FarmerLogin;
