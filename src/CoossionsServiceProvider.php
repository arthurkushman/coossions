<?php
/**
 * Created by PhpStorm.
 * User: arthur
 * Date: 05.04.17
 * Time: 22:14
 */

namespace coossions;


use Illuminate\Support\ServiceProvider;

/**
 * ServiceProvider implementation for Laravel
 *
 * Class CoossionsServiceProvider
 * @package coossions
 */
class CoossionsServiceProvider extends ServiceProvider
{
    protected $defer = true;

    protected $secret = '';

    public function __construct(\Illuminate\Foundation\Application $app, $secret)
    {
        $this->secret = $secret;
        parent::__construct($app);
    }

    /**
     * Register the application services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->bind('coossions\base\CoossionsContractInterface', function($app, $secret) {
            return new CoossionsHandler($secret);
        });
    }

    /**
     * Get the services DI provided by the provider.
     *
     * @return array
     */
    public function provides()
    {
        return ['coossions\base\CoossionsContractInterface'];
    }
}