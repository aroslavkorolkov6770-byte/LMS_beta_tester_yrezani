import { NextResponse } from 'next/server';
import {
    applySessionCookie,
    getCurrentStoredUser,
    getStoredUsers,
    saveStoredUsers,
    toPublicUser,
    toSessionUser,
    verifyPassword,
} from '@/app/lib/serverAuth';
import { getLoginValidationError } from '@/app/lib/loginValidation';
import {
    assertRateLimit,
    assertTrustedMutationRequest,
    getClientIdentifier,
    readJsonBody,
    securityErrorResponse,
} from '@/app/lib/serverSecurity';

export const dynamic = 'force-dynamic';

export async function PUT(request: Request) {
    try {
        assertTrustedMutationRequest(request);
        const currentUser = await getCurrentStoredUser();
        if (!currentUser) {
            return NextResponse.json({ error: 'Требуется авторизация' }, { status: 401 });
        }

        assertRateLimit('account-login', getClientIdentifier(request, currentUser.id), 10, 60 * 60 * 1000);
        const body = await readJsonBody<{ login?: unknown; currentPassword?: unknown }>(request, 8 * 1024);
        const login = typeof body.login === 'string' ? body.login.trim() : '';
        const currentPassword = typeof body.currentPassword === 'string' ? body.currentPassword : '';
        const validationError = getLoginValidationError(login);
        if (validationError) {
            return NextResponse.json({ error: validationError }, { status: 400 });
        }
        if (!currentPassword || currentPassword.length > 128 || !verifyPassword(currentUser, currentPassword)) {
            return NextResponse.json({ error: 'Текущий пароль указан неверно' }, { status: 403 });
        }

        const users = await getStoredUsers();
        if (users.some(user => user.id !== currentUser.id && user.login === login)) {
            return NextResponse.json({ error: 'Логин уже занят другим пользователем' }, { status: 409 });
        }

        // ID остаётся прежним: профиль, обучение и личные сообщения не переносятся и не удаляются.
        // Версия доступа меняется только при реальном изменении, чтобы завершить прежние сессии.
        const updatedUser = login === currentUser.login ? currentUser : {
            ...currentUser,
            login,
            authVersion: (currentUser.authVersion || 0) + 1,
        };
        if (login !== currentUser.login) {
            await saveStoredUsers(users.map(user => user.id === currentUser.id ? updatedUser : user));
        }

        const response = NextResponse.json({ success: true, user: toPublicUser(updatedUser) });
        applySessionCookie(response, toSessionUser(updatedUser));
        return response;
    } catch (error) {
        const securityResponse = securityErrorResponse(error);
        if (securityResponse) return securityResponse;
        console.error('Ошибка смены логина:', error);
        return NextResponse.json({ error: 'Не удалось изменить логин' }, { status: 500 });
    }
}
