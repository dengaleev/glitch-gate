INSERT INTO url (
    long_url,
    short_url,
    created_at,
    updated_at
) VALUES (
    $1,
    $2,
    NOW(),
    NOW()
);
