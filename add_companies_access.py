from app import app, db, FeatureAccess

# Выполняем код в контексте приложения
with app.app_context():
    # Проверяем, существует ли уже запись для доступа к компаниям
    existing = FeatureAccess.query.filter_by(feature='companies', target_type='department', target_id='ALL').first()
    
    if not existing:
        # Добавляем доступ для всех отделов
        db.session.add(FeatureAccess(
            target_type='department',
            target_id='ALL',
            feature='companies',
            access=True
        ))
        db.session.commit()
        print("✅ Доступ к модулю 'Информация о компаниях' добавлен для всех отделов")
    else:
        print("ℹ️ Доступ к модулю 'Информация о компаниях' уже существует") 