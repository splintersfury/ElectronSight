/* ElectronSight — Extra JavaScript */

document$.subscribe(function() {
  /* Animate stat numbers on page load */
  const statNumbers = document.querySelectorAll('.es-stat-number');
  statNumbers.forEach(function(el) {
    el.style.opacity = '0';
    el.style.transform = 'translateY(10px)';
    setTimeout(function() {
      el.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
      el.style.opacity = '1';
      el.style.transform = 'translateY(0)';
    }, 100);
  });

  /* Pipeline step hover chain effect */
  const steps = document.querySelectorAll('.es-pipeline-step');
  steps.forEach(function(step, i) {
    step.addEventListener('mouseenter', function() {
      steps.forEach(function(s, j) {
        if (j <= i) {
          s.style.borderColor = 'var(--es-accent)';
          s.style.background = 'var(--es-accent-dim)';
        }
      });
    });
    step.addEventListener('mouseleave', function() {
      steps.forEach(function(s) {
        s.style.borderColor = '';
        s.style.background = '';
      });
    });
  });
});
