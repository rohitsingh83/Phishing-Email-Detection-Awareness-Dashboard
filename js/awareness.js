/**
 * Security Awareness & Interactive Training Controller
 */
document.addEventListener("DOMContentLoaded", () => {
  // Tab switching for micro-lessons
  const tabButtons = document.querySelectorAll(".lesson-tab-btn");
  const lessonContents = document.querySelectorAll(".lesson-content");

  tabButtons.forEach(button => {
    button.addEventListener("click", () => {
      const targetId = button.getAttribute("data-tab");

      tabButtons.forEach(btn => btn.classList.remove("active"));
      lessonContents.forEach(content => content.classList.remove("active"));

      button.classList.add("active");
      const targetContent = document.getElementById(targetId);
      if (targetContent) {
        targetContent.classList.add("active");
      }
    });
  });

  // Interactive Checklist Progress
  const checkboxes = document.querySelectorAll(".checklist-container input[type='checkbox']");
  checkboxes.forEach(box => {
    box.addEventListener("change", () => {
      const checkedCount = document.querySelectorAll(".checklist-container input[type='checkbox']:checked").length;
      if (checkedCount === checkboxes.length) {
        // All checked! Give visual celebration
        box.closest(".panel").style.borderColor = "var(--accent-green)";
      } else {
        box.closest(".panel").style.borderColor = "var(--border-color)";
      }
    });
  });
});
