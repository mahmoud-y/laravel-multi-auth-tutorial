<?php

use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});

Auth::routes(['verify' => true]);

Route::get('/home', 'HomeController@index')->name('home');

Route::get('/confirmed', function () {
    return 'password confirmed';
})->middleware(['auth', 'password.confirm']);

Route::get('/verified', function () {
    return 'email verified';
})->middleware('verified');

Route::group(['prefix' => '/admin', 'namespace' => 'Admin', 'as' => 'admin.'], function () {
    Route::get('/', function () {
        return view('admin.welcome');
    });
    
    Auth::routes(['verify' => true]);
    
    Route::get('/home', 'HomeController@index')->name('admin.home');
    
    Route::get('/confirmed', function () {
        return 'password confirmed';
    })->middleware(['auth:admin-web', 'password.confirm:admin.password.confirm']);
    
    Route::get('/verified', function () {
        return 'email verified';
    })->middleware('verified:admin.verification.notice,admin-web');
});
