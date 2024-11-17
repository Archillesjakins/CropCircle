import React, { useEffect, useRef } from 'react';
import { gsap } from 'gsap';
import backgroundImage from '../../assets/images/backgroundImage.jpg';
// import '../../styles/HomePage/HomePage.css';

const HeroSection = () => {
  const texts = [
    "Empowering Small-Scale Farmers",
    "with Direct Access",
    "to Sustainable Markets"
  ];

  // Create refs for each text line
  const textRefs = useRef([]);

  // Scroll to FarmersSection function
  const scrollToSection = () => {
    const targetSection = document.getElementById("FarmersSection");
    if (targetSection) {
      targetSection.scrollIntoView({ behavior: "smooth" });
    }
  };

  useEffect(() => {
    if (textRefs.current.length > 0) {
      // GSAP animation to fade in each text line with a stagger effect
      gsap.fromTo(
        textRefs.current,
        { y: 50, opacity: 0 },
        {
          y: 0,
          opacity: 1,
          duration: 1.5,
          stagger: 0.3,
          ease: "power3.out",
        }
      );
    }
  }, []);

  return (
    <div
      className="relative bg-cover bg-center h-screen"
      style={{ backgroundImage: `url(${backgroundImage})` }}
    >
      {/* Gradient overlay */}
      <div
        className="absolute inset-0 bg-gradient-to-b from-black via-transparent to-black opacity-75"
        aria-hidden="true"
      ></div>

      {/* Content Container */}
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center px-4">
        <div className="text-white">
          {texts.map((text, index) => (
            <div
              key={index}
              ref={(el) => (textRefs.current[index] = el)}
              className="text-xl md:text-3xl lg:text-5xl font-bold mb-4"
            >
              {text}
            </div>
          ))}
        </div>
        {/* Call-to-Action Button */}
        <button
          onClick={scrollToSection}
          className="mt-6 px-6 py-3 bg-green-500 text-white text-lg md:text-xl font-semibold rounded-lg shadow-lg hover:bg-green-600 focus:outline-none focus:ring-4 focus:ring-green-400"
        >
          Learn More
        </button>
      </div>
    </div>
  );
};

export default HeroSection;
