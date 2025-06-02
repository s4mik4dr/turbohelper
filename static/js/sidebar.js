document.addEventListener('DOMContentLoaded', () => {
    const sidebar = document.getElementById('sidebar');
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const mobileSidebarToggle = document.getElementById('mobile-sidebar-toggle');
    const mainContent = document.querySelector('.main-content');
    
    // Проверяем сохраненное состояние сайдбара
    const sidebarState = localStorage.getItem('sidebarCollapsed') === 'true';
    if (sidebarState) {
        sidebar.classList.add('collapsed');
        mainContent.classList.add('expanded');
    }
    
    // Обработчик для десктопного переключателя
    sidebarToggle.addEventListener('click', () => {
        sidebar.classList.toggle('collapsed');
        mainContent.classList.toggle('expanded');
        
        // Сохраняем состояние
        localStorage.setItem('sidebarCollapsed', sidebar.classList.contains('collapsed'));
    });
    
    // Обработчик для мобильного переключателя
    mobileSidebarToggle.addEventListener('click', () => {
        sidebar.classList.toggle('mobile-open');
    });
    
    // Закрываем сайдбар при клике вне его на мобильных устройствах
    document.addEventListener('click', (e) => {
        if (window.innerWidth <= 768) {
            if (!sidebar.contains(e.target) && 
                !mobileSidebarToggle.contains(e.target) && 
                sidebar.classList.contains('mobile-open')) {
                sidebar.classList.remove('mobile-open');
            }
        }
    });
    
    // Обработка ховера на пунктах меню
    const menuItems = document.querySelectorAll('.menu-item');
    menuItems.forEach(item => {
        item.addEventListener('mouseenter', () => {
            if (sidebar.classList.contains('collapsed')) {
                const tooltip = document.createElement('div');
                tooltip.className = 'menu-tooltip';
                tooltip.textContent = item.querySelector('span').textContent;
                
                const rect = item.getBoundingClientRect();
                tooltip.style.top = `${rect.top}px`;
                tooltip.style.left = `${rect.right + 10}px`;
                
                document.body.appendChild(tooltip);
                
                item.addEventListener('mouseleave', () => {
                    tooltip.remove();
                }, { once: true });
            }
        });
    });
    
    // Адаптивность: автоматически сворачиваем сайдбар на маленьких экранах
    const handleResize = () => {
        if (window.innerWidth <= 768) {
            sidebar.classList.add('collapsed');
            mainContent.classList.add('expanded');
        }
    };
    
    window.addEventListener('resize', handleResize);
    handleResize(); // Вызываем сразу при загрузке
}); 